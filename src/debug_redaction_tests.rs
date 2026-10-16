//! `Debug` output must never contain secret key material, session keys or passphrases.

use bytes::{Bytes, BytesMut};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use zeroize::Zeroizing;

use crate::{
    composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder},
    crypto::{ecc_curve::ECCCurve, ecdh, ecdsa, eddsa_legacy, public_key::PublicKeyAlgorithm},
    types::{KeyVersion, Mpi, Password, PlainSecret, PlainSecretParams},
};

/// A secret no real key contains, so finding it in output can only mean a leak.
pub(crate) const SECRET: &[u8] = b"\x5e\xc2\xe7\x00debug-canary-secret\x01\x02\x03";

/// Fails if `out` contains `secret` in any of the forms `Debug` would print it.
pub(crate) fn assert_redacted(out: &str, secret: &[u8], what: &str) {
    let hex = hex::encode(secret);
    let upper = hex.to_uppercase();
    // `{:?}` of a byte slice, without its brackets.
    let list = format!("{:?}", &secret[..8]);
    let list = list.trim_start_matches('[').trim_end_matches(']');
    for form in [&hex[..16], &upper[..16], list] {
        assert!(
            !out.contains(form),
            "{what}: Debug output contains {form:?}: {out}"
        );
    }
}

#[test]
fn opaque_secret_variants_are_redacted() {
    let unknown = PlainSecretParams::Unknown {
        alg: PublicKeyAlgorithm::Unknown(99),
        data: Zeroizing::new(SECRET.to_vec()),
        pub_params: Bytes::new(),
    };
    assert_redacted(
        &format!("{unknown:?}"),
        SECRET,
        "PlainSecretParams::Unknown",
    );

    let ecdh = ecdh::SecretKey::Unsupported {
        curve: ECCCurve::BrainpoolP256r1,
        mpi_data: BytesMut::from(SECRET),
    };
    assert_redacted(&format!("{ecdh:?}"), SECRET, "ecdh::SecretKey::Unsupported");

    let ecdsa = ecdsa::SecretKey::Unsupported {
        curve: ECCCurve::BrainpoolP256r1,
        mpi_data: BytesMut::from(SECRET),
    };
    assert_redacted(
        &format!("{ecdsa:?}"),
        SECRET,
        "ecdsa::SecretKey::Unsupported",
    );

    let eddsa = eddsa_legacy::SecretKey::Unsupported {
        curve: ECCCurve::BrainpoolP256r1,
        opaque: BytesMut::from(SECRET),
    };
    assert_redacted(
        &format!("{eddsa:?}"),
        SECRET,
        "eddsa_legacy::SecretKey::Unsupported",
    );
}

#[test]
fn mpi_is_redacted() {
    let mpi = Mpi::from_slice(SECRET);
    assert_redacted(&format!("{mpi:?}"), &SECRET[4..], "Mpi");
}

#[test]
fn builder_passphrase_is_redacted() {
    let pass = "debug-canary-passphrase-0123456789";
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .primary_user_id("debug <debug@example.com>".into())
        .passphrase(Some(pass.into()))
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                .can_encrypt(EncryptionCaps::All)
                .passphrase(Some(pass.into()))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let out = format!("{params:?}");
    assert!(!out.contains(pass), "SecretKeyParams: {out}");
}

/// Generated keys of every type EFV uses: nothing in the key's `Debug` shows its secrets.
#[test]
fn keys_are_redacted() {
    for (version, primary, sub) in [
        (
            KeyVersion::V4,
            KeyType::Ed25519Legacy,
            KeyType::ECDH(ECCCurve::Curve25519Legacy),
        ),
        (KeyVersion::V6, KeyType::Ed25519, KeyType::X25519),
        (KeyVersion::V4, KeyType::Rsa(2048), KeyType::Rsa(2048)),
        #[cfg(feature = "pqc")]
        (
            KeyVersion::V6,
            KeyType::MlDsa65Ed25519,
            KeyType::MlKem768X25519,
        ),
    ] {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let key = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(primary.clone())
            .can_sign(true)
            .primary_user_id("debug <debug@example.com>".into())
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(sub)
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
            .generate(&mut rng)
            .unwrap();

        let out = format!("{key:?}");
        let check = |plain: &PlainSecretParams| {
            assert_redacted(&format!("{plain:?}"), &raw(plain), "PlainSecretParams");
            assert_redacted(&out, &raw(plain), &format!("{primary:?} key"));
            Ok(())
        };
        key.primary_key
            .unlock(&Password::empty(), |_, p| check(p))
            .unwrap()
            .unwrap();
        for sub in &key.secret_subkeys {
            sub.key
                .unlock(&Password::empty(), |_, p| check(p))
                .unwrap()
                .unwrap();
        }
    }
}

/// The serialized secret, which is what `PlainSecret` holds.
fn raw(plain: &PlainSecretParams) -> Zeroizing<Vec<u8>> {
    let held = PlainSecret::new(PublicKeyAlgorithm::Unknown(0), plain);
    let out = format!("{held:?}");
    let raw = plain.to_raw();
    assert_redacted(&out, &raw, "PlainSecret");
    // Skip the MPI length header, so the window is secret bytes only.
    Zeroizing::new(raw[2..].to_vec())
}
