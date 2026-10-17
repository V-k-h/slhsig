//! Verification of attacker-chosen keys, contexts, messages and signatures: never panics, and
//! never accepts (an arbitrary input forging a signature would be a break of SLH-DSA).
#![no_main]

use libfuzzer_sys::fuzz_target;
use slhsig::*;

fn verify<P: ParameterSet>(data: &[u8]) {
    if data.len() < P::PK_BYTES + 1 {
        return;
    }
    let (pk, rest) = data.split_at(P::PK_BYTES);
    let ctx_len = usize::from(rest[0]).min(rest.len() - 1);
    let (ctx, rest) = rest[1..].split_at(ctx_len);
    let msg_len = rest.len().min(64);
    let (msg, sig) = rest.split_at(msg_len);
    let vk = VerifyingKey::<P>::from_slice(pk).expect("length checked");
    let ctx = Context::new(ctx).expect("at most 255 bytes");
    // Pad short inputs so the full verification path runs, not just the length check.
    let mut padded = sig.to_vec();
    padded.resize(P::SIG_BYTES, 0);
    assert!(vk.verify_bytes(msg, ctx, &padded).is_err());
    assert!(vk.verify_bytes(msg, ctx, sig).is_err());
}

fuzz_target!(|data: &[u8]| {
    match data.first().map(|b| b % 2) {
        Some(0) => verify::<Sha2_128f>(&data[1..]),
        Some(_) => verify::<Shake128f>(&data[1..]),
        None => {}
    }
});
