//! The optional `signature` trait impls and `serde` support.

use signature::{Keypair, RandomizedSigner, SignatureEncoding, Signer, Verifier};
use slhsig::*;

#[test]
fn signature_traits_use_the_empty_context() {
    let sk = SigningKey::<Shake128f>::generate().unwrap();
    let vk = Keypair::verifying_key(&sk);
    let sig = RandomizedSigner::try_sign_with_rng(&sk, &mut getrandom::SysRng, b"m").unwrap();
    assert!(Verifier::verify(&vk, b"m", &sig).is_ok());
    assert!(vk.verify(b"m", Context::EMPTY, &sig).is_ok());
    assert!(Verifier::verify(&vk, b"n", &sig).is_err());
    assert_eq!(SignatureEncoding::to_bytes(&sig).as_ref(), sig.as_bytes());

    let det = SigningKey::<Shake128f, Deterministic>::generate().unwrap();
    let a: Signature<Shake128f> = Signer::try_sign(&det, b"m").unwrap();
    assert_eq!(a, det.sign(b"m", Context::EMPTY).unwrap());
}

#[test]
fn serde_round_trips_public_values_only() {
    let sk = SigningKey::<Shake128f>::generate().unwrap();
    let vk = sk.verifying_key();
    let sig = sk.sign(b"m", Context::EMPTY).unwrap();

    let vk_json = serde_json::to_string(&vk).unwrap();
    let vk_back: VerifyingKey<Shake128f> = serde_json::from_str(&vk_json).unwrap();
    assert_eq!(vk_back, vk);

    let sig_json = serde_json::to_string(&sig).unwrap();
    let sig_back: Signature<Shake128f> = serde_json::from_str(&sig_json).unwrap();
    assert_eq!(sig_back, sig);

    // Wrong lengths are rejected, not truncated or padded.
    assert!(serde_json::from_str::<VerifyingKey<Shake128f>>("[1,2,3]").is_err());
}
