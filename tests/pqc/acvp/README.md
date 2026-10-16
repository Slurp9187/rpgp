# NIST ACVP ML-DSA vectors

These are trimmed copies of the FIPS 204 ML-DSA vectors from
[usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server), commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, at
`gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json`.

They keep only the parameter sets rPGP uses (ML-DSA-65 and ML-DSA-87), and only the
external, pure interface (no pre-hash, no external mu), which is the one OpenPGP uses
(RFC 9980):

- keyGen: 5 cases per parameter set (seed to public key).
- sigGen: 3 deterministic and 3 hedged (with `rnd`) cases per parameter set.
- sigVer: 3 passing and 3 failing cases per parameter set.

Fields the tests don't read were dropped. The tests are in `src/crypto/ml_dsa_acvp.rs`.
