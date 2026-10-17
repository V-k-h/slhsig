# slhsig

SLH-DSA, the stateless hash-based signature scheme of [FIPS 205], in pure Rust, written from
the standard's pseudocode.

> **Status: experimental (0.1.0).** It passes all NIST ACVP vectors for the 12 parameter sets
> and agrees byte-for-byte with two independent implementations, but it has **not been
> independently reviewed**. Do not use it to protect anything that matters until it has been.

```rust
use slhsig::{Context, Shake128f, SigningKey};

let sk = SigningKey::<Shake128f>::generate()?;      // hedged signing, OS entropy
let vk = sk.verifying_key();
let ctx = Context::new(b"example-protocol v1")?;   // at most 255 bytes
let sig = sk.sign(b"message", ctx)?;               // signed twice and compared by default
vk.verify(b"message", ctx, &sig)?;
```

## What it implements

- All 12 FIPS 205 parameter sets, each a type behind a Cargo feature.
- Pure signing (Algorithm 22) and HashSLH-DSA (Algorithm 23) with SHA-256, SHA-512, SHAKE128
  and SHAKE256. SHA-256 and SHAKE128 are refused for category 3 and 5 sets (FIPS 205 §10.2.2).
- Hedged signing by default; deterministic signing as a separate key type,
  `SigningKey<P, Deterministic>`, because FIPS 205 asks that a key serve one variant only.
- Context strings, validated on construction.
- A fault check on every signature. By default it signs twice and compares
  (`FaultCheck::Redundant`), because one faulted SLH-DSA signature can enable universal forgery
  ([ePrint 2018/102]) and such signatures still verify. This roughly doubles signing time;
  `FaultCheck::Verify` (verify before returning) and `FaultCheck::None` are opt-outs.
- Raw FIPS 205 encodings for keys and signatures. Secret-key import recomputes PK.root and
  rejects inconsistent keys.

| Parameter set | Category | Public key | Secret key | Signature |
| --- | --- | --- | --- | --- |
| `Sha2_128s`, `Shake128s` | 1 | 32 B | 64 B | 7,856 B |
| `Sha2_128f`, `Shake128f` | 1 | 32 B | 64 B | 17,088 B |
| `Sha2_192s`, `Shake192s` | 3 | 48 B | 96 B | 16,224 B |
| `Sha2_192f`, `Shake192f` | 3 | 48 B | 96 B | 35,664 B |
| `Sha2_256s`, `Shake256s` | 5 | 64 B | 128 B | 29,792 B |
| `Sha2_256f`, `Shake256f` | 5 | 64 B | 128 B | 49,856 B |

## Security properties

Claimed, with the evidence in this repository:

- **FIPS 205 output.** Identical to the standard for every set, variant and interface: NIST ACVP
  keyGen (120 cases), sigGen (624) and sigVer (504) vectors, in `tests/acvp.rs`.
- **Agreement with independent implementations.** Keys and deterministic and hedged signatures
  are byte-identical with RustCrypto `slh-dsa` and integritychain `fips205`, and each accepts
  the others' signatures: `testkit/tests/differential.rs`.
- **No secret-dependent control flow or memory access** in key generation and signing. Secrets
  only enter hash inputs; every index the signer uses is recomputed by verifiers. Key generation
  is measured with dudect (`dudect/`).
- **No panics on untrusted input.** Exact-length parsing; fuzz targets in `fuzz/`.
- **Bounded memory.** Signing makes one heap allocation (the signature). All operations for all
  sets run on a 64 KiB stack (`tests/stack.rs`).
- **Zeroization.** Secret seeds and intermediates are zeroized on drop (best effort; it cannot
  erase compiler-made copies or swapped pages). No `unsafe` code.

Not claimed: message-bound signatures (FIPS 205 §11), constant-time verification (its inputs are
public), protection against a compromised host, or FIPS 140-3 validation.

## Cargo features

| Feature | Default | Effect |
| --- | --- | --- |
| `sha2-128f`, `shake-128f` | yes | Parameter sets enabled by default |
| `sha2-128s` ... `shake-256f`, `all-parameter-sets` | no | The other ten sets |
| `os-rng` | yes | `SigningKey::generate` and hedged `sign` via `getrandom::SysRng` |
| `signature-traits` | no | RustCrypto `signature` 3 traits (pure, empty context) |
| `serde` | no | Serialize public keys and signatures as bytes |
| `hazmat` | no | FIPS 205 internal functions for test vectors. **Never in production.** |

The crate is `no_std` with `alloc`. MSRV: Rust 1.88.

## Testing

```sh
cargo test --all-features                       # unit, API, ACVP, stack and integration tests
cargo test -p slhsig-testkit --release          # differential tests (SLHSIG_DIFF_CASES=n)
cargo run --release -p slhsig-dudect            # timing measurements
cd fuzz && cargo +nightly fuzz run verify       # fuzzing (requires cargo-fuzz)
cargo bench --all-features                      # benchmarks
```

ACVP vectors come from [usnistgov/ACVP-Server] at the commit in `tests/acvp/SOURCE_COMMIT`.

## Server use

Signing is CPU-bound, and slow for the "s" sets. Run it with `spawn_blocking` or a dedicated
pool, cap concurrency with a semaphore, and alert on `Error::SelfCheckFailed`, which points at
faulty hardware. Pin the parameter set and the pure or pre-hash mode in your protocol; never
select them from untrusted input.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

[FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205
[ePrint 2018/102]: https://eprint.iacr.org/2018/102
[usnistgov/ACVP-Server]: https://github.com/usnistgov/ACVP-Server
