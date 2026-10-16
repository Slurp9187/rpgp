//! NIST ACVP ML-DSA vectors (FIPS 204) for the parameter sets rPGP uses, ML-DSA-65 and ML-DSA-87.
//!
//! The vectors are a trimmed subset of the ACVP-Server `internalProjection.json` files; see
//! `tests/pqc/acvp/README.md` for their provenance.

use ml_dsa::{MlDsa65, MlDsa87};
use serde::Deserialize;

#[derive(Deserialize)]
struct File<T> {
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group<T>>,
}

#[derive(Deserialize)]
struct Group<T> {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(default)]
    deterministic: Option<bool>,
    tests: Vec<T>,
}

#[derive(Deserialize)]
struct KeyGen {
    seed: String,
    pk: String,
}

#[derive(Deserialize)]
struct SigGen {
    sk: String,
    message: String,
    context: String,
    signature: String,
    #[serde(default)]
    rnd: Option<String>,
}

/// Hands out the ACVP `rnd` value as the hedged signer's 32 random bytes, and nothing else.
struct FixedRnd(Option<[u8; 32]>);

impl ml_dsa::common::rand_core::TryRng for FixedRnd {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!("ML-DSA asks for 32 bytes")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!("ML-DSA asks for 32 bytes")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&self.0.take().expect("rnd used once"));
        Ok(())
    }
}

impl ml_dsa::common::rand_core::TryCryptoRng for FixedRnd {}

#[derive(Deserialize)]
struct SigVer {
    pk: String,
    message: String,
    context: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

fn load<T: serde::de::DeserializeOwned>(name: &str) -> Vec<Group<T>> {
    let path = format!("{}/tests/pqc/acvp/{name}", env!("CARGO_MANIFEST_DIR"));
    let file: File<T> = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
    file.test_groups
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

macro_rules! acvp_tests {
    ($module:ident, $params:ty, $name:literal) => {
        mod $module {
            use super::*;

            type P = $params;

            #[test]
            fn key_gen() {
                let mut count = 0;
                for group in load::<KeyGen>("ML-DSA-keyGen-FIPS204.json") {
                    if group.parameter_set != $name {
                        continue;
                    }
                    for t in group.tests {
                        let seed: [u8; 32] = unhex(&t.seed).try_into().unwrap();
                        let sk = ml_dsa::SigningKey::<P>::from_seed(&seed.into());
                        let vk: &ml_dsa::VerifyingKey<P> = sk.as_ref();
                        assert_eq!(vk.encode().as_slice(), &unhex(&t.pk)[..]);
                        count += 1;
                    }
                }
                assert!(count > 0);
            }

            #[test]
            fn sig_gen_deterministic() {
                let mut count = 0;
                for group in load::<SigGen>("ML-DSA-sigGen-FIPS204.json") {
                    if group.parameter_set != $name || group.deterministic != Some(true) {
                        continue;
                    }
                    for t in group.tests {
                        let sk_bytes =
                            ml_dsa::ExpandedSigningKeyBytes::<P>::try_from(&unhex(&t.sk)[..])
                                .unwrap();
                        #[allow(deprecated)]
                        let sk = ml_dsa::ExpandedSigningKey::<P>::from_expanded(&sk_bytes);
                        let sig = sk
                            .sign_deterministic(&unhex(&t.message), &unhex(&t.context))
                            .unwrap();
                        assert_eq!(sig.encode().as_slice(), &unhex(&t.signature)[..]);
                        count += 1;
                    }
                }
                assert!(count > 0);
            }

            #[test]
            fn sig_gen_hedged() {
                let mut count = 0;
                for group in load::<SigGen>("ML-DSA-sigGen-FIPS204.json") {
                    if group.parameter_set != $name || group.deterministic != Some(false) {
                        continue;
                    }
                    for t in group.tests {
                        let sk_bytes =
                            ml_dsa::ExpandedSigningKeyBytes::<P>::try_from(&unhex(&t.sk)[..])
                                .unwrap();
                        #[allow(deprecated)]
                        let sk = ml_dsa::ExpandedSigningKey::<P>::from_expanded(&sk_bytes);
                        let rnd = unhex(t.rnd.as_deref().unwrap()).try_into().unwrap();
                        let sig = sk
                            .sign_randomized(
                                &unhex(&t.message),
                                &unhex(&t.context),
                                &mut FixedRnd(Some(rnd)),
                            )
                            .unwrap();
                        assert_eq!(sig.encode().as_slice(), &unhex(&t.signature)[..]);
                        count += 1;
                    }
                }
                assert!(count > 0);
            }

            #[test]
            fn sig_ver() {
                let (mut pass, mut fail) = (0, 0);
                for group in load::<SigVer>("ML-DSA-sigVer-FIPS204.json") {
                    if group.parameter_set != $name {
                        continue;
                    }
                    for t in group.tests {
                        let pk =
                            ml_dsa::EncodedVerifyingKey::<P>::try_from(&unhex(&t.pk)[..]).unwrap();
                        let vk = ml_dsa::VerifyingKey::<P>::decode(&pk);
                        let ok = ml_dsa::Signature::<P>::try_from(&unhex(&t.signature)[..])
                            .map(|sig| {
                                vk.verify_with_context(&unhex(&t.message), &unhex(&t.context), &sig)
                            })
                            .unwrap_or(false);
                        assert_eq!(ok, t.test_passed);
                        if t.test_passed {
                            pass += 1;
                        } else {
                            fail += 1;
                        }
                    }
                }
                assert!(pass > 0 && fail > 0);
            }
        }
    };
}

acvp_tests!(ml_dsa_65, MlDsa65, "ML-DSA-65");
acvp_tests!(ml_dsa_87, MlDsa87, "ML-DSA-87");
