# Changelog

All notable changes are documented here. The format follows Keep a Changelog, and the project
follows Semantic Versioning.

## 0.1.0 (unreleased)

### Added
- SLH-DSA (FIPS 205) for all 12 parameter sets, written from the standard's pseudocode.
- Pure and pre-hash (HashSLH-DSA) signing and verification; hedged and deterministic key types.
- `Context`, `PreHashed` and `KeyUsage` validation; fault checks (`Verify`, `Redundant`).
- Checked secret-key import that recomputes PK.root.
- Optional `signature` 3 trait impls, `serde` for public keys and signatures, and `hazmat`
  internal functions for test vectors.
- NIST ACVP tests (keyGen, sigGen, sigVer), differential tests against RustCrypto `slh-dsa`
  and integritychain `fips205`, fuzz targets, a dudect harness, a stack-budget test and
  benchmarks.
- Mutation-testing configuration (`.cargo/mutants.toml`) listing the equivalent mutants.
