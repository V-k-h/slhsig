//! Stack budget: key generation, signing (with the redundant fault check) and verification for
//! every parameter set must complete on a thread with a small, fixed stack.
//!
//! `cargo test` builds this crate at opt-level 3 with debug assertions on ([profile.test]).

use slhsig::*;

/// The design document's proposed budget for optimized builds.
const BUDGET: usize = 64 * 1024;

fn exercise<P: ParameterSet>() {
    let seeds = [7u8; 96];
    let sk = SigningKey::<P, Deterministic>::try_generate(&mut Seeds(&seeds[..3 * P::N]))
        .unwrap()
        .with_fault_check(FaultCheck::Redundant);
    let sk = SigningKey::<P, Deterministic>::from_bytes(&sk.to_bytes())
        .unwrap()
        .with_fault_check(FaultCheck::Redundant);
    let sig = sk.sign(b"stack", Context::EMPTY).unwrap();
    assert!(sk.verifying_key().verify(b"stack", Context::EMPTY, &sig).is_ok());
}

/// Replays fixed seed bytes.
struct Seeds<'a>(&'a [u8]);

impl rand_core::TryRng for Seeds<'_> {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!()
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let (head, tail) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = tail;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Seeds<'_> {}

fn on_small_stack(f: fn()) {
    std::thread::Builder::new()
        .stack_size(BUDGET)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("operation overflowed or panicked on the budgeted stack");
}

macro_rules! stack_tests {
    ($($name:ident => $set:ty),* $(,)?) => {$(
        #[test]
        fn $name() {
            on_small_stack(exercise::<$set>);
        }
    )*};
}

stack_tests!(
    sha2_128s => Sha2_128s,
    sha2_128f => Sha2_128f,
    sha2_192s => Sha2_192s,
    sha2_192f => Sha2_192f,
    sha2_256s => Sha2_256s,
    sha2_256f => Sha2_256f,
    shake_128s => Shake128s,
    shake_128f => Shake128f,
    shake_192s => Shake192s,
    shake_192f => Shake192f,
    shake_256s => Shake256s,
    shake_256f => Shake256f,
);
