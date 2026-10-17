//! Differential tests: slhsig against RustCrypto `slh-dsa` and integritychain `fips205`.
//!
//! For each case (random seeds, message of 0-2048 bytes, context of 0-255 bytes, addrnd):
//! 1. key generation from the same seeds gives identical keys in all three;
//! 2. deterministic signatures are byte-identical in all three;
//! 3. hedged signatures with the same addrnd are byte-identical in all three;
//! 4. each implementation accepts the others' signatures and rejects a one-bit corruption.
//!
//! `SLHSIG_DIFF_CASES` and `SLHSIG_DIFF_CASES_S` set the number of cases per "f" and "s"
//! parameter set (the scheduled CI job raises both).

use fips205::traits::{KeyGen, SerDes, Signer as _, Verifier as _};
use slhsig::{Context, Deterministic, FaultCheck, Hedged, ParameterSet, Signature, SigningKey};
use slhsig_testkit::{Cases, Fixed, Fixed06, case_count};

fn seed_for(name: &str) -> u64 {
    // FNV-1a, so every test function gets its own reproducible stream.
    name.bytes()
        .fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}

macro_rules! differential {
    ($($name:ident: $ours:ty, $rc:ty, $fips:ident, $default:expr;)*) => {$(
        #[test]
        fn $name() {
            type P = $ours;
            let n = <P as ParameterSet>::N;
            let mut cases = Cases::new(seed_for(stringify!($name)));
            for case in 0..case_count(<P as ParameterSet>::NAME, $default) {
                let seeds = cases.bytes(3 * n);
                let msg_len = cases.len(2048);
                let msg = cases.bytes(msg_len);
                let ctx_len = cases.len(255);
                let ctx = cases.bytes(ctx_len);
                let addrnd = cases.bytes(n);
                let context = Context::new(&ctx).unwrap();
                let at = |what: &str| format!("{} case {case}: {what}", <P as ParameterSet>::NAME);

                // 1. Key generation from identical seeds (FIPS 205 Algorithm 21 order).
                // The fault check never changes the output, so it is off here for speed.
                let ours = SigningKey::<P, Deterministic>::try_generate(&mut Fixed(&seeds))
                    .unwrap()
                    .with_fault_check(FaultCheck::None);
                let ours_hedged = SigningKey::<P, Hedged>::try_generate(&mut Fixed(&seeds))
                    .unwrap()
                    .with_fault_check(FaultCheck::None);
                let sk_bytes = ours.to_bytes();
                let vk = ours.verifying_key();
                let pk_bytes = vk.to_bytes();

                let rc_sk = slh_dsa::SigningKey::<$rc>::new(&mut Fixed(&seeds));
                assert_eq!(rc_sk.to_vec(), sk_bytes.as_ref(), "{}", at("RustCrypto secret key"));
                let rc_vk: &slh_dsa::VerifyingKey<$rc> = rc_sk.as_ref();

                let seed = |range: core::ops::Range<usize>| -> [u8; fips205::$fips::N] {
                    seeds[range].try_into().unwrap()
                };
                let (fpk, fsk) = fips205::$fips::KG::keygen_with_seeds(
                    &seed(0..n),
                    &seed(n..2 * n),
                    &seed(2 * n..3 * n),
                );
                assert_eq!(&fpk.clone().into_bytes()[..], pk_bytes.as_ref(), "{}", at("fips205 public key"));
                assert_eq!(&fsk.clone().into_bytes()[..], sk_bytes.as_ref(), "{}", at("fips205 secret key"));

                // 2. Deterministic signatures.
                let det = ours.sign(&msg, context).unwrap();
                let rc_det = rc_sk.try_sign_with_context(&msg, &ctx, None).unwrap();
                assert_eq!(rc_det.to_vec(), det.as_bytes(), "{}", at("RustCrypto deterministic signature"));
                let f_det = fsk.try_sign_with_rng(&mut Fixed06(&[]), &msg, &ctx, false).unwrap();
                assert_eq!(&f_det[..], det.as_bytes(), "{}", at("fips205 deterministic signature"));

                // 3. Hedged signatures with the same addrnd.
                let hedged = ours_hedged.try_sign(&mut Fixed(&addrnd), &msg, context).unwrap();
                let rc_hedged = rc_sk.try_sign_with_context(&msg, &ctx, Some(&addrnd)).unwrap();
                assert_eq!(rc_hedged.to_vec(), hedged.as_bytes(), "{}", at("RustCrypto hedged signature"));
                let f_hedged = fsk.try_sign_with_rng(&mut Fixed06(&addrnd), &msg, &ctx, true).unwrap();
                assert_eq!(&f_hedged[..], hedged.as_bytes(), "{}", at("fips205 hedged signature"));
                assert_ne!(hedged, det);

                // 4. Cross-verification, and rejection of a one-bit corruption by all three.
                let theirs = Signature::<P>::from_slice(&rc_hedged.to_vec()).unwrap();
                assert!(vk.verify(&msg, context, &theirs).is_ok(), "{}", at("ours rejects RustCrypto"));
                let ours_for_rc = slh_dsa::Signature::<$rc>::try_from(hedged.as_bytes()).unwrap();
                assert!(rc_vk.try_verify_with_context(&msg, &ctx, &ours_for_rc).is_ok(), "{}", at("RustCrypto rejects ours"));
                assert!(fpk.verify(&msg, &hedged.as_bytes().try_into().unwrap(), &ctx), "{}", at("fips205 rejects ours"));

                let mut bad = hedged.as_bytes().to_vec();
                let byte = (cases.next_u64() % bad.len() as u64) as usize;
                bad[byte] ^= 1 << (cases.next_u64() % 8);
                assert!(vk.verify_bytes(&msg, context, &bad).is_err(), "{}", at("ours accepts corruption"));
                let bad_rc = slh_dsa::Signature::<$rc>::try_from(&bad[..]).unwrap();
                assert!(rc_vk.try_verify_with_context(&msg, &ctx, &bad_rc).is_err(), "{}", at("RustCrypto accepts corruption"));
                assert!(!fpk.verify(&msg, &bad[..].try_into().unwrap(), &ctx), "{}", at("fips205 accepts corruption"));
            }
        }
    )*};
}

differential! {
    sha2_128s: slhsig::Sha2_128s, slh_dsa::Sha2_128s, slh_dsa_sha2_128s, 4;
    sha2_128f: slhsig::Sha2_128f, slh_dsa::Sha2_128f, slh_dsa_sha2_128f, 25;
    sha2_192s: slhsig::Sha2_192s, slh_dsa::Sha2_192s, slh_dsa_sha2_192s, 4;
    sha2_192f: slhsig::Sha2_192f, slh_dsa::Sha2_192f, slh_dsa_sha2_192f, 25;
    sha2_256s: slhsig::Sha2_256s, slh_dsa::Sha2_256s, slh_dsa_sha2_256s, 4;
    sha2_256f: slhsig::Sha2_256f, slh_dsa::Sha2_256f, slh_dsa_sha2_256f, 25;
    shake_128s: slhsig::Shake128s, slh_dsa::Shake128s, slh_dsa_shake_128s, 4;
    shake_128f: slhsig::Shake128f, slh_dsa::Shake128f, slh_dsa_shake_128f, 25;
    shake_192s: slhsig::Shake192s, slh_dsa::Shake192s, slh_dsa_shake_192s, 4;
    shake_192f: slhsig::Shake192f, slh_dsa::Shake192f, slh_dsa_shake_192f, 25;
    shake_256s: slhsig::Shake256s, slh_dsa::Shake256s, slh_dsa_shake_256s, 4;
    shake_256f: slhsig::Shake256f, slh_dsa::Shake256f, slh_dsa_shake_256f, 25;
}
