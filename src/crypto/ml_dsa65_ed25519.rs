use ml_dsa::MlDsa65;
use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{ensure, ensure_eq, format_err, Result},
    ser::Serialize,
    types::{MlDsa65Ed25519PublicParams, SignatureBytes},
};

/// Size in bytes of the ED25519 secret key.
pub const ED25519_KEY_LEN: usize = 32;
/// Size in bytes of the ML DSA 65 secret key.
pub const ML_DSA65_KEY_LEN: usize = 32;

/// Secret key for ML DSA 65 with Curve25519.
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    #[debug("..")]
    ed25519: ed25519_dalek::SigningKey,
    /// Holds the 32-byte seed and the expanded key, and wipes both on drop.
    #[debug("{}", hex::encode(AsRef::<ml_dsa::VerifyingKey<_>>::as_ref(&**ml_dsa).encode()))]
    ml_dsa: Box<ml_dsa::SigningKey<MlDsa65>>,
}

impl Eq for SecretKey {}

impl ZeroizeOnDrop for SecretKey {}

impl From<&SecretKey> for MlDsa65Ed25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            ed25519: value.ed25519.verifying_key(),
            ml_dsa: Box::new(value.ml_dsa_verifying_key().clone()),
        }
    }
}

impl SecretKey {
    /// Generate an Ed448 `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let ed25519 = ed25519_dalek::SigningKey::generate(&mut rng);
        let mut ml_dsa_seed = [0u8; ML_DSA65_KEY_LEN];
        rng.fill_bytes(&mut ml_dsa_seed);
        let ml_dsa = Box::new(ml_dsa::SigningKey::from_seed(&ml_dsa_seed.into()));
        ml_dsa_seed.zeroize();

        SecretKey { ed25519, ml_dsa }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(ed25519: [u8; 32], ml_dsa: [u8; 32]) -> Result<Self> {
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&ed25519);
        // use the seed format
        let ml_dsa = Box::new(ml_dsa::SigningKey::from_seed(&ml_dsa.into()));

        Ok(Self { ed25519, ml_dsa })
    }

    /// Returns the individual secret keys in their raw byte level representation.
    /// The first is the `ed25519` and the second the `ml dsa 65` key.
    pub fn as_bytes(&self) -> (&[u8; ED25519_KEY_LEN], &[u8; ML_DSA65_KEY_LEN]) {
        (self.ed25519.as_bytes(), self.ml_dsa.as_seed().as_ref())
    }

    /// Returns the ML-DSA verifying key, which the signing key precomputes.
    fn ml_dsa_verifying_key(&self) -> &ml_dsa::VerifyingKey<MlDsa65> {
        (*self.ml_dsa).as_ref()
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        ensure!(
            ![
                HashAlgorithm::Md5,
                HashAlgorithm::Ripemd160,
                HashAlgorithm::Sha1
            ]
            .contains(&hash),
            "invalid hash algorithm"
        );

        let ed25519_sig = self.ed25519.sign(digest);
        let mut bytes = ed25519_sig.to_bytes().to_vec();

        // Hedged ML-DSA.Sign with fresh randomness, as RFC 9980 §5.2 specifies; the deterministic
        // variant gives up the side-channel resistance §9.3 describes.
        let ml_dsa_sig = self
            .ml_dsa
            .expanded_key()
            .sign_randomized(digest, &[], &mut ml_dsa::common::getrandom::SysRng)
            .map_err(|e| format_err!("ML-DSA signing failed: {}", e))?;
        bytes.extend_from_slice(&ml_dsa_sig.encode());

        Ok(SignatureBytes::Native(bytes.into()))
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let (x, ml) = self.as_bytes();
        writer.write_all(x)?;
        writer.write_all(ml)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        ED25519_KEY_LEN + ML_DSA65_KEY_LEN
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    ed_key: &ed25519_dalek::VerifyingKey,
    ml_dsa_key: &ml_dsa::VerifyingKey<MlDsa65>,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    ensure!(
        ![
            HashAlgorithm::Md5,
            HashAlgorithm::Ripemd160,
            HashAlgorithm::Sha1
        ]
        .contains(&hash),
        "invalid hash algorithm"
    );
    ensure_eq!(sig_bytes.len(), 64 + 3309, "invalid signature length");

    let ed_sig = ed25519_dalek::Signature::try_from(&sig_bytes[..64])?;
    ed_key.verify(hashed, &ed_sig)?;

    let ml_sig = ml_dsa::Signature::<MlDsa65>::try_from(&sig_bytes[64..])
        .map_err(|_| format_err!("invalid ML-DSA signature encoding"))?;
    ensure!(
        ml_dsa_key.verify_with_context(hashed, &[], &ml_sig),
        "invalid ML-DSA signature"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    impl Arbitrary for SecretKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<u64>()
                .prop_map(|seed| {
                    let mut rng = ChaCha8Rng::seed_from_u64(seed);
                    SecretKey::generate(&mut rng)
                })
                .boxed()
        }
    }

    /// A composite signature made by rPGP 0.21.0 with ml-dsa 0.0.4, from fixed key bytes over a
    /// fixed digest (`tests/pqc/fork-mldsa-65-0.0.4-raw.bin`).
    const SIG_0_0_4: &[u8] = include_bytes!("../../tests/pqc/fork-mldsa-65-0.0.4-raw.bin");
    const DIGEST: [u8; 32] = [0x5a; 32];

    fn fixture_key() -> SecretKey {
        SecretKey::try_from_bytes([0x24; 32], [0x42; 32]).unwrap()
    }

    fn verify_with(public: &crate::types::MlDsa65Ed25519PublicParams, sig: &[u8]) -> Result<()> {
        verify(
            &public.ed25519,
            &public.ml_dsa,
            HashAlgorithm::Sha3_256,
            &DIGEST,
            sig,
        )
    }

    #[test]
    fn verifies_ml_dsa_0_0_4_signature() {
        let public = (&fixture_key()).into();
        verify_with(&public, SIG_0_0_4).unwrap();

        // Flipping a byte of the ML-DSA half must fail.
        let mut tampered = SIG_0_0_4.to_vec();
        tampered[64 + 100] ^= 1;
        assert!(verify_with(&public, &tampered).is_err());
    }

    #[test]
    fn seed_round_trips() {
        let key = fixture_key();
        assert_eq!(key.as_bytes().1, &[0x42; 32]);
    }

    fn sign(key: &SecretKey) -> Vec<u8> {
        let SignatureBytes::Native(sig) = key.sign(HashAlgorithm::Sha3_256, &DIGEST).unwrap()
        else {
            panic!("expected native signature bytes");
        };
        sig.to_vec()
    }

    #[test]
    fn hedged_signatures_differ_and_verify() {
        let key = fixture_key();
        let public = (&key).into();
        let (a, b) = (sign(&key), sign(&key));
        assert_ne!(a, b, "hedged signing must not repeat");
        assert_ne!(
            a, SIG_0_0_4,
            "hedged signing must not match the deterministic signature"
        );
        for sig in [a, b] {
            verify_with(&public, &sig).unwrap();
        }
    }
}
