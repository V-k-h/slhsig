//! Public API behavior: round trips, negative cases, usage locks, fault checks and encodings.

mod common;

use common::{FailingRng, FixedRng};
use slhsig::*;

const SEED: [u8; 96] = [0x5a; 96];

/// A deterministic key from fixed seeds, so failures reproduce.
fn key<P: ParameterSet, V: Variant>() -> SigningKey<P, V> {
    let mut rng = FixedRng::new(&SEED[..3 * P::N]);
    SigningKey::<P, V>::try_generate(&mut rng).unwrap()
}

fn ctx(bytes: &[u8]) -> Context<'_> {
    Context::new(bytes).unwrap()
}

fn round_trip_and_binding<P: ParameterSet>() {
    let sk = key::<P, Hedged>();
    let vk = sk.verifying_key();
    let addrnd = [0x11u8; 32];
    let sig = sk.try_sign(&mut FixedRng::new(&addrnd[..P::N]), b"message", ctx(b"ctx")).unwrap();
    assert_eq!(sig.as_bytes().len(), P::SIG_BYTES);
    assert!(vk.verify(b"message", ctx(b"ctx"), &sig).is_ok());

    // Message, context and key are all bound into the signature.
    assert!(vk.verify(b"messagf", ctx(b"ctx"), &sig).is_err());
    assert!(vk.verify(b"message", ctx(b"ctY"), &sig).is_err());
    assert!(vk.verify(b"message", Context::EMPTY, &sig).is_err());
    let mut other = [0x5bu8; 96];
    other[0] = 0;
    let other_vk = SigningKey::<P>::try_generate(&mut FixedRng::new(&other[..3 * P::N]))
        .unwrap()
        .verifying_key();
    assert!(other_vk.verify(b"message", ctx(b"ctx"), &sig).is_err());

    // Hedged signing with different randomness gives a different, still valid signature.
    let addrnd2 = [0x22u8; 32];
    let sig2 = sk.try_sign(&mut FixedRng::new(&addrnd2[..P::N]), b"message", ctx(b"ctx")).unwrap();
    assert_ne!(sig, sig2);
    assert!(vk.verify(b"message", ctx(b"ctx"), &sig2).is_ok());

    // Deterministic signing is reproducible and differs from hedged output.
    let det = key::<P, Deterministic>();
    let d1 = det.sign(b"message", ctx(b"ctx")).unwrap();
    let d2 = det.sign(b"message", ctx(b"ctx")).unwrap();
    assert_eq!(d1, d2);
    assert_ne!(d1, sig);
    assert!(det.verifying_key().verify(b"message", ctx(b"ctx"), &d1).is_ok());
}

/// Flips one bit in R, in SIG_FORS, and in every hypertree layer: each must fail.
fn every_component_is_checked<P: ParameterSet>() {
    let sk = key::<P, Deterministic>();
    let vk = sk.verifying_key();
    let sig = sk.sign(b"flip", Context::EMPTY).unwrap();
    let n = P::N;
    let fors_end = n + P::K * (1 + P::A) * n;
    let layer = (P::HP + P::LEN) * n;
    let mut offsets = vec![0, n - 1, n, fors_end - 1];
    for j in 0..P::D {
        offsets.push(fors_end + j * layer); // first WOTS+ chain of layer j
        offsets.push(fors_end + (j + 1) * layer - 1); // last auth node of layer j
    }
    for at in offsets {
        let mut bad = sig.as_bytes().to_vec();
        bad[at] ^= 0x01;
        assert!(vk.verify_bytes(b"flip", Context::EMPTY, &bad).is_err(), "flip at byte {at}");
    }
    // Lengths off by one are rejected at parse time.
    let mut longer = sig.as_bytes().to_vec();
    longer.push(0);
    assert_eq!(Signature::<P>::from_slice(&longer), Err(Error::InvalidSignatureLength));
    assert_eq!(
        Signature::<P>::from_slice(&sig.as_bytes()[..P::SIG_BYTES - 1]),
        Err(Error::InvalidSignatureLength)
    );
    assert!(vk.verify_bytes(b"flip", Context::EMPTY, &longer).is_err());
}

fn prehash_usage<P: ParameterSet>() {
    let mut sk = key::<P, Deterministic>();
    let vk = sk.verifying_key();
    let digest = PreHash::Sha512.digest(b"large content");

    // A fresh key is pure-only.
    assert_eq!(sk.sign_prehashed(digest.as_prehashed(), Context::EMPTY), Err(Error::UsageMismatch));

    sk.set_usage(KeyUsage::PreHash(PreHash::Sha512)).unwrap();
    let sig = sk.sign_prehashed(digest.as_prehashed(), ctx(b"c")).unwrap();
    assert!(vk.verify_prehashed(digest.as_prehashed(), ctx(b"c"), &sig).is_ok());
    // Domain separation: a pre-hash signature is not a pure signature over the digest.
    assert!(vk.verify(digest.as_prehashed().digest(), ctx(b"c"), &sig).is_err());
    // A pre-hash key refuses pure signing and other hash functions.
    assert_eq!(sk.sign(b"x", Context::EMPTY), Err(Error::UsageMismatch));
    let other = PreHash::Shake256.digest(b"large content");
    assert_eq!(sk.sign_prehashed(other.as_prehashed(), Context::EMPTY), Err(Error::UsageMismatch));

    // SHA-256 and SHAKE128 are category 1 only.
    for weak in [PreHash::Sha256, PreHash::Shake128] {
        let result = sk.set_usage(KeyUsage::PreHash(weak));
        if P::CATEGORY == 1 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(Error::PreHashTooWeak));
        }
    }
}

fn encodings_and_checked_import<P: ParameterSet>() {
    let sk = key::<P, Hedged>();
    let bytes = sk.to_bytes();
    assert_eq!(bytes.as_ref().len(), P::SK_BYTES);
    let back = SigningKey::<P>::from_bytes(&bytes).unwrap();
    assert_eq!(back.verifying_key(), sk.verifying_key());

    // A corrupted PK.root is caught by the checked import.
    let mut bad = bytes.as_ref().to_vec();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(SigningKey::<P>::from_slice(&bad).err(), Some(Error::InconsistentKey));
    assert_eq!(SigningKey::<P>::from_slice(&bad[1..]).err(), Some(Error::InvalidKeyLength));

    // ...and the unchecked import of the same key fails the default fault check at first use.
    let unchecked = SigningKey::<P, Deterministic>::from_bytes_unchecked(
        &<P::SkBytes as TryFrom<&[u8]>>::try_from(&bad[..]).ok().unwrap(),
    );
    assert_eq!(unchecked.sign(b"m", Context::EMPTY), Err(Error::SelfCheckFailed));

    let vk_bytes = sk.verifying_key().to_bytes();
    assert_eq!(VerifyingKey::<P>::from_slice(vk_bytes.as_ref()).unwrap(), sk.verifying_key());
    assert_eq!(
        VerifyingKey::<P>::from_slice(&vk_bytes.as_ref()[1..]).err(),
        Some(Error::InvalidKeyLength)
    );
}

macro_rules! per_set {
    ($($module:ident => $set:ty),* $(,)?) => {$(
        mod $module {
            use super::*;
            #[test] fn round_trip() { round_trip_and_binding::<$set>(); }
            #[test] fn components() { every_component_is_checked::<$set>(); }
            #[test] fn prehash() { prehash_usage::<$set>(); }
            #[test] fn encodings() { encodings_and_checked_import::<$set>(); }
        }
    )*};
}

per_set!(
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

#[test]
fn context_length_limit() {
    let long = [0u8; 256];
    assert_eq!(Context::new(&long[..255]).map(|c| c.as_bytes().len()), Ok(255));
    assert_eq!(Context::new(&long), Err(Error::ContextTooLong));
}

#[test]
fn prehashed_length_is_checked() {
    assert_eq!(PreHashed::new(PreHash::Sha256, &[0u8; 31]), Err(Error::InvalidDigestLength));
    assert_eq!(PreHashed::new(PreHash::Sha512, &[0u8; 32]), Err(Error::InvalidDigestLength));
    assert!(PreHashed::new(PreHash::Shake256, &[0u8; 64]).is_ok());
}

#[test]
fn rng_failure_is_an_error() {
    assert_eq!(SigningKey::<Shake128f>::try_generate(&mut FailingRng).err(), Some(Error::Entropy));
    let sk = key::<Shake128f, Hedged>();
    assert_eq!(sk.try_sign(&mut FailingRng, b"m", Context::EMPTY), Err(Error::Entropy));
}

#[test]
fn fault_check_modes_all_sign() {
    for mode in [FaultCheck::None, FaultCheck::Verify, FaultCheck::Redundant] {
        let sk = key::<Sha2_128f, Deterministic>().with_fault_check(mode);
        assert_eq!(sk.fault_check(), mode);
        let sig = sk.sign(b"m", Context::EMPTY).unwrap();
        assert!(sk.verifying_key().verify(b"m", Context::EMPTY, &sig).is_ok());
    }
}

#[test]
fn debug_output_has_no_secrets() {
    let sk = key::<Shake128f, Hedged>();
    let debug = format!("{sk:?}");
    let secret_hex: String =
        sk.to_bytes().as_ref()[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert!(debug.contains("SLH-DSA-SHAKE-128f"));
    assert!(!debug.contains(&secret_hex));
}

#[cfg(feature = "os-rng")]
#[test]
fn os_rng_path() {
    let sk = SigningKey::<Shake128f>::generate().unwrap();
    let sig = sk.sign(b"m", Context::EMPTY).unwrap();
    assert!(sk.verifying_key().verify(b"m", Context::EMPTY, &sig).is_ok());
}

#[test]
fn types_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<SigningKey<Shake128f, Hedged>>();
    check::<SigningKey<Sha2_256s, Deterministic>>();
    check::<VerifyingKey<Sha2_192f>>();
    check::<Signature<Shake256s>>();
}

#[test]
fn redundant_is_the_default_fault_check() {
    assert_eq!(FaultCheck::default(), FaultCheck::Redundant);
    assert_eq!(key::<Shake128f, Hedged>().fault_check(), FaultCheck::Redundant);
    let imported =
        SigningKey::<Shake128f>::from_bytes(&key::<Shake128f, Hedged>().to_bytes()).unwrap();
    assert_eq!(imported.fault_check(), FaultCheck::Redundant);
}

fn hash_of<T: core::hash::Hash>(value: &T) -> u64 {
    use core::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn set_fault_check_takes_effect() {
    let mut sk = key::<Shake128f, Hedged>();
    sk.set_fault_check(FaultCheck::None);
    assert_eq!(sk.fault_check(), FaultCheck::None);
    sk.set_fault_check(FaultCheck::Verify);
    assert_eq!(sk.fault_check(), FaultCheck::Verify);
}

#[test]
fn error_messages() {
    let errors = [
        Error::ContextTooLong,
        Error::InvalidKeyLength,
        Error::InvalidSignatureLength,
        Error::InvalidDigestLength,
        Error::PreHashTooWeak,
        Error::UsageMismatch,
        Error::InconsistentKey,
        Error::Entropy,
        Error::SelfCheckFailed,
    ];
    let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
    for (i, message) in messages.iter().enumerate() {
        assert!(!message.is_empty());
        assert!(!messages[..i].contains(message), "duplicate message {message:?}");
    }
    assert_eq!(Error::ContextTooLong.to_string(), "context string longer than 255 bytes");
    assert_eq!(VerificationError.to_string(), "signature verification failed");
}

#[test]
fn verifying_key_equality_hash_and_debug() {
    let vk = key::<Shake128f, Hedged>().verifying_key();
    let bytes = vk.to_bytes();
    let same = VerifyingKey::<Shake128f>::from_slice(bytes.as_ref()).unwrap();
    assert_eq!(same, vk);
    assert_eq!(hash_of(&same), hash_of(&vk));

    // Flip one bit of PK.seed, then one bit of PK.root: each alone makes the keys differ.
    for at in [0, Shake128f::N] {
        let mut other = bytes.as_ref().to_vec();
        other[at] ^= 1;
        let other = VerifyingKey::<Shake128f>::from_slice(&other).unwrap();
        assert_ne!(other, vk);
        assert_ne!(hash_of(&other), hash_of(&vk));
    }

    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(format!("{vk:?}"), format!("VerifyingKey<SLH-DSA-SHAKE-128f>({hex})"));
}

#[test]
fn signature_encodings_hash_and_debug() {
    let sk = key::<Shake128f, Deterministic>();
    let sig = sk.sign(b"m", Context::EMPTY).unwrap();
    assert_eq!(sig.as_ref(), sig.as_bytes());
    assert_eq!(sig.as_bytes().len(), Shake128f::SIG_BYTES);

    let from_vec = Signature::<Shake128f>::from_vec(sig.as_bytes().to_vec()).unwrap();
    assert_eq!(from_vec, sig);
    assert_eq!(hash_of(&from_vec), hash_of(&sig));
    for len in [0, Shake128f::SIG_BYTES - 1, Shake128f::SIG_BYTES + 1] {
        assert_eq!(
            Signature::<Shake128f>::from_vec(vec![0; len]).err(),
            Some(Error::InvalidSignatureLength)
        );
    }

    let other = sk.sign(b"n", Context::EMPTY).unwrap();
    assert_ne!(other, sig);
    assert_ne!(hash_of(&other), hash_of(&sig));

    // Debug shows the randomizer R and the length, not the whole signature.
    let r: String = sig.as_bytes()[..Shake128f::N].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        format!("{sig:?}"),
        format!("Signature<SLH-DSA-SHAKE-128f>(R = {r}, {} bytes)", Shake128f::SIG_BYTES)
    );
}
