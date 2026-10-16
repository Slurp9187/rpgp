//! Holding secret bytes, sealed while idle.
//!
//! With the `sealed-secrets` feature, [`SecretBytes`] keeps its bytes encrypted (AES-256-GCM)
//! under a random key made once per process, and decrypts them only for the duration of
//! [`SecretBytes::with_open`], into a buffer that is wiped afterwards. An idle secret then never
//! sits in memory in readable form: not in the heap, a core dump, a swap or hibernation image,
//! or a crash report.
//!
//! It does not protect a secret while it is open, and an attacker who can read the process's
//! memory can also find the process key. Without the feature, the bytes are held as they are,
//! and wiped on drop.
//!
//! This module uses no rPGP types, so it can move into a separate crate.

use zeroize::Zeroizing;

/// Secret bytes, sealed while idle when the `sealed-secrets` feature is on. Wiped on drop.
#[derive(Clone)]
pub(crate) struct SecretBytes {
    #[cfg(not(feature = "sealed-secrets"))]
    raw: Zeroizing<Vec<u8>>,
    #[cfg(feature = "sealed-secrets")]
    sealed: sealing::Sealed,
}

impl SecretBytes {
    /// Holds `raw`, sealing it if the feature is on.
    pub(crate) fn new(raw: Zeroizing<Vec<u8>>) -> Self {
        #[cfg(not(feature = "sealed-secrets"))]
        {
            Self { raw }
        }
        #[cfg(feature = "sealed-secrets")]
        {
            Self {
                sealed: sealing::Sealed::seal(&raw),
            }
        }
    }

    /// The length of the secret.
    pub(crate) fn len(&self) -> usize {
        #[cfg(not(feature = "sealed-secrets"))]
        {
            self.raw.len()
        }
        #[cfg(feature = "sealed-secrets")]
        {
            self.sealed.len()
        }
    }

    /// Runs `f` on the secret, opening it first if it is sealed.
    pub(crate) fn with_open<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        #[cfg(not(feature = "sealed-secrets"))]
        {
            f(&self.raw)
        }
        #[cfg(feature = "sealed-secrets")]
        {
            let open = self.sealed.open();
            f(&open)
        }
    }

    /// Compares two secrets in constant time (in their contents).
    pub(crate) fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.with_open(|a| other.with_open(|b| bool::from(a.ct_eq(b))))
    }
}

#[cfg(feature = "sealed-secrets")]
mod sealing {
    use std::sync::OnceLock;

    use aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes256Gcm, Nonce,
    };
    use rand::RngCore;
    use zeroize::Zeroizing;

    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    /// The per-process sealing key, made from the OS RNG on first use.
    fn process_key() -> &'static Zeroizing<[u8; 32]> {
        static KEY: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut key = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut key[..]);
            key
        })
    }

    fn cipher() -> Aes256Gcm {
        Aes256Gcm::new(process_key()[..].into())
    }

    /// Ciphertext and tag, with the random nonce they were sealed under.
    #[derive(Clone)]
    pub(super) struct Sealed {
        nonce: [u8; NONCE_LEN],
        /// Ciphertext followed by the tag.
        data: Vec<u8>,
    }

    impl Sealed {
        pub(super) fn seal(plain: &[u8]) -> Self {
            let mut nonce = [0u8; NONCE_LEN];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            // Room for the tag up front, so the plaintext is never reallocated; it is
            // encrypted in place before anything else can happen to it.
            let mut data = Vec::with_capacity(plain.len() + TAG_LEN);
            data.extend_from_slice(plain);
            cipher()
                .encrypt_in_place(Nonce::from_slice(&nonce), b"", &mut data)
                .expect("AES-GCM encryption of a small buffer does not fail");
            Self { nonce, data }
        }

        pub(super) fn len(&self) -> usize {
            self.data.len() - TAG_LEN
        }

        /// Decrypts into a buffer that wipes on drop.
        pub(super) fn open(&self) -> Zeroizing<Vec<u8>> {
            let mut out = Zeroizing::new(self.data.clone());
            cipher()
                .decrypt_in_place(Nonce::from_slice(&self.nonce), b"", &mut *out)
                .expect("sealed in this process, under this process's key");
            out
        }

        #[cfg(test)]
        pub(super) fn ciphertext(&self) -> &[u8] {
            &self.data
        }
    }
}

impl SecretBytes {
    /// The bytes as held while idle: the ciphertext when sealed, else the secret itself.
    #[cfg(test)]
    pub(crate) fn idle_bytes(&self) -> &[u8] {
        #[cfg(not(feature = "sealed-secrets"))]
        {
            &self.raw
        }
        #[cfg(feature = "sealed-secrets")]
        {
            self.sealed.ciphertext()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &[u8] = b"sealed-bytes-canary-0123456789abcdef";

    #[test]
    fn round_trip() {
        let held = SecretBytes::new(Zeroizing::new(CANARY.to_vec()));
        assert_eq!(held.len(), CANARY.len());
        held.with_open(|b| assert_eq!(b, CANARY));
        assert!(held.ct_eq(&held.clone()));
        assert!(!held.ct_eq(&SecretBytes::new(Zeroizing::new(b"other".to_vec()))));
    }

    /// Idle, the held bytes are ciphertext: the canary is nowhere in them, and two seals of the
    /// same secret differ (fresh nonces).
    #[cfg(feature = "sealed-secrets")]
    #[test]
    fn idle_bytes_are_sealed() {
        let a = SecretBytes::new(Zeroizing::new(CANARY.to_vec()));
        let b = SecretBytes::new(Zeroizing::new(CANARY.to_vec()));
        let ct = a.sealed.ciphertext();
        assert!(
            !ct.windows(8).any(|w| CANARY.windows(8).any(|c| c == w)),
            "plaintext visible in the sealed form"
        );
        assert_ne!(ct, b.sealed.ciphertext());
    }
}
