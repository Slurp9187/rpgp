use ml_dsa::MlDsa87;
use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{ensure, ensure_eq, format_err, Result},
    ser::Serialize,
    types::{MlDsa87Ed448PublicParams, SignatureBytes},
};

/// Size in bytes of the ED448 secret key.
pub const ED448_KEY_LEN: usize = 57;
/// Size in bytes of the ML DSA 87 secret key.
pub const ML_DSA87_KEY_LEN: usize = 32;

/// Secret key for ML DSA 87 with Curve448.
#[derive(Clone, PartialEq, derive_more::Debug)]
pub struct SecretKey {
    /// The secret point.
    #[debug("..")]
    ed448: cx448::SigningKey,
    /// Holds the 32-byte seed and the expanded key, and wipes both on drop.
    #[debug("{}", hex::encode(AsRef::<ml_dsa::VerifyingKey<_>>::as_ref(&**ml_dsa).encode()))]
    ml_dsa: Box<ml_dsa::SigningKey<MlDsa87>>,
}

impl Eq for SecretKey {}

impl ZeroizeOnDrop for SecretKey {}

impl From<&SecretKey> for MlDsa87Ed448PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            ed448: value.ed448.verifying_key(),
            ml_dsa: Box::new(value.ml_dsa_verifying_key().clone()),
        }
    }
}

impl SecretKey {
    /// Generate an Ed448 `SecretKey`.
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let ed448 = cx448::SigningKey::generate(&mut rng);
        let mut ml_dsa_seed = [0u8; ML_DSA87_KEY_LEN];
        rng.fill_bytes(&mut ml_dsa_seed);
        let ml_dsa = Box::new(ml_dsa::SigningKey::from_seed(&ml_dsa_seed.into()));
        ml_dsa_seed.zeroize();

        SecretKey { ed448, ml_dsa }
    }

    /// Create a key from the raw byte values
    pub fn try_from_bytes(
        ed448: [u8; ED448_KEY_LEN],
        ml_dsa: [u8; ML_DSA87_KEY_LEN],
    ) -> Result<Self> {
        let ed448 = cx448::SigningKey::from(cx448::SecretKey::from_slice(&ed448));
        // use the seed format
        let ml_dsa = Box::new(ml_dsa::SigningKey::from_seed(&ml_dsa.into()));

        Ok(Self { ed448, ml_dsa })
    }

    /// Returns the individual secret keys in their raw byte level representation.
    /// The first is the `ed448` and the second the `ml dsa 87` key.
    pub fn as_bytes(&self) -> (&[u8; ED448_KEY_LEN], &[u8; ML_DSA87_KEY_LEN]) {
        let r: &[u8] = self.ed448.as_bytes().as_ref();
        (
            r.try_into().expect("known size"),
            self.ml_dsa.as_seed().as_ref(),
        )
    }

    /// Returns the ML-DSA verifying key, which the signing key precomputes.
    fn ml_dsa_verifying_key(&self) -> &ml_dsa::VerifyingKey<MlDsa87> {
        (*self.ml_dsa).as_ref()
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
        ED448_KEY_LEN + ML_DSA87_KEY_LEN
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

        let ed448_sig = self.ed448.sign(digest);
        let mut bytes = ed448_sig.to_bytes().to_vec();
        let ml_dsa_sig = self
            .ml_dsa
            .expanded_key()
            .sign_deterministic(digest, &[])
            .map_err(|e| format_err!("ML-DSA signing failed: {}", e))?;
        bytes.extend_from_slice(&ml_dsa_sig.encode());

        Ok(SignatureBytes::Native(bytes.into()))
    }
}

/// Verify an EdDSA signature.
pub fn verify(
    ed_key: &cx448::VerifyingKey,
    ml_dsa_key: &ml_dsa::VerifyingKey<MlDsa87>,
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
    ensure_eq!(sig_bytes.len(), 114 + 4627, "invalid signature length");

    let ed_sig = cx448::Signature::try_from(&sig_bytes[..114])?;
    ed_key.verify(hashed, &ed_sig)?;

    let ml_sig = ml_dsa::Signature::<MlDsa87>::try_from(&sig_bytes[114..])
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
    /// fixed digest (`tests/pqc/fork-mldsa-87-0.0.4-raw.bin`).
    const SIG_0_0_4: &[u8] = include_bytes!("../../tests/pqc/fork-mldsa-87-0.0.4-raw.bin");
    const DIGEST: [u8; 64] = [0x5a; 64];

    fn fixture_key() -> SecretKey {
        SecretKey::try_from_bytes([0x24; 57], [0x42; 32]).unwrap()
    }

    #[test]
    fn verifies_ml_dsa_0_0_4_signature() {
        let key = fixture_key();
        let public = crate::types::MlDsa87Ed448PublicParams::from(&key);
        verify(
            &public.ed448,
            &public.ml_dsa,
            HashAlgorithm::Sha3_512,
            &DIGEST,
            SIG_0_0_4,
        )
        .unwrap();

        // Flipping a byte of the ML-DSA half must fail.
        let mut tampered = SIG_0_0_4.to_vec();
        tampered[114 + 100] ^= 1;
        assert!(verify(
            &public.ed448,
            &public.ml_dsa,
            HashAlgorithm::Sha3_512,
            &DIGEST,
            &tampered,
        )
        .is_err());
    }

    #[test]
    fn seed_round_trips() {
        let key = fixture_key();
        assert_eq!(key.as_bytes().1, &[0x42; 32]);
    }

    #[test]
    fn deterministic_matches_ml_dsa_0_0_4() {
        let SignatureBytes::Native(sig) = fixture_key()
            .sign(HashAlgorithm::Sha3_512, &DIGEST)
            .unwrap()
        else {
            panic!("expected native signature bytes");
        };
        assert_eq!(&sig[..], SIG_0_0_4);
    }
}
