//! Keys, messages and contexts derived from the input: signing succeeds, the signature
//! verifies, and a one-bit change to it does not.
#![no_main]

use libfuzzer_sys::fuzz_target;
use slhsig::*;

struct Bytes<'a>(&'a [u8]);

impl rand_core::TryRng for Bytes<'_> {
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

impl rand_core::TryCryptoRng for Bytes<'_> {}

fn round_trip<P: ParameterSet>(data: &[u8]) {
    let need = 3 * P::N + 3;
    if data.len() < need {
        return;
    }
    let (seeds, rest) = data.split_at(3 * P::N);
    let ctx_len = usize::from(rest[0]).min(rest.len() - 3);
    let flip = usize::from(u16::from_le_bytes([rest[1], rest[2]]));
    let (ctx, msg) = rest[3..].split_at(ctx_len);
    let sk = SigningKey::<P, Deterministic>::try_generate(&mut Bytes(seeds)).unwrap();
    let ctx = Context::new(ctx).unwrap();
    let sig = sk.sign(msg, ctx).unwrap();
    let vk = sk.verifying_key();
    assert!(vk.verify(msg, ctx, &sig).is_ok());
    let mut bad = sig.into_bytes().into_vec();
    let at = flip % bad.len();
    bad[at] ^= 1 << (flip % 8);
    assert!(vk.verify_bytes(msg, ctx, &bad).is_err());
}

fuzz_target!(|data: &[u8]| {
    match data.first().map(|b| b % 2) {
        Some(0) => round_trip::<Sha2_128f>(&data[1..]),
        Some(_) => round_trip::<Shake128f>(&data[1..]),
        None => {}
    }
});
