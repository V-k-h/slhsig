//! dudect (Reparaz, Balasch, Verbauwhede 2017) timing test of key generation.
//!
//! Class Left uses one fixed SK.seed; class Right draws a fresh random SK.seed per sample.
//! PK.seed is identical in both classes, so every input that may legitimately steer timing is
//! the same and only the secret differs. Key generation does a fixed amount of work (every
//! WOTS+ chain runs w - 1 steps), so a timing difference would point at secret-dependent
//! behavior in the hash backends or in this crate.
//!
//! Signing is not measured this way: its work depends on the message digest, which is derived
//! from the secret PRF key but is public (verifiers recompute it). A fixed-versus-random-key
//! test would therefore report that public variation as a leak.
//!
//! Run with `cargo run --release -p slhsig-dudect -- --continuous keygen_shake128f`, or without
//! arguments for one pass over every benchmark. |t| values above 5 indicate a leak.

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use rand_core::Rng;
use slhsig::*;

const SAMPLES: usize = 5_000;

struct Seeds<'a>(&'a [u8]);

impl rand_core::TryRng for Seeds<'_> {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let (head, tail) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = tail;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Seeds<'_> {}

fn keygen<P: ParameterSet>(runner: &mut CtRunner, rng: &mut BenchRng) {
    let n = P::N;
    let mut inputs = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let mut seeds = vec![0u8; 3 * n];
        let class = if rng.next_u32() & 1 == 0 {
            seeds[..2 * n].fill(0x11);
            Class::Left
        } else {
            rng.fill_bytes(&mut seeds[..2 * n]);
            Class::Right
        };
        seeds[2 * n..].fill(0x42); // PK.seed: public, identical in both classes
        inputs.push((class, seeds));
    }
    for (class, seeds) in inputs {
        runner.run_one(class, || {
            SigningKey::<P, Deterministic>::try_generate(&mut Seeds(&seeds)).unwrap()
        });
    }
}

fn keygen_sha2_128f(runner: &mut CtRunner, rng: &mut BenchRng) {
    keygen::<Sha2_128f>(runner, rng)
}

fn keygen_shake128f(runner: &mut CtRunner, rng: &mut BenchRng) {
    keygen::<Shake128f>(runner, rng)
}

fn keygen_sha2_192f(runner: &mut CtRunner, rng: &mut BenchRng) {
    keygen::<Sha2_192f>(runner, rng)
}

fn keygen_shake256f(runner: &mut CtRunner, rng: &mut BenchRng) {
    keygen::<Shake256f>(runner, rng)
}

ctbench_main!(keygen_sha2_128f, keygen_shake128f, keygen_sha2_192f, keygen_shake256f);
