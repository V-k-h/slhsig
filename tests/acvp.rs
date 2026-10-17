//! NIST ACVP test vectors for SLH-DSA (FIPS 205): keyGen, sigGen and sigVer for all 12 sets.
//!
//! Source: usnistgov/ACVP-Server, gen-val/json-files/SLH-DSA-*-FIPS205/internalProjection.json,
//! at the commit in tests/acvp/SOURCE_COMMIT (checksums in tests/acvp/SHA256SUMS).
//!
//! Every case runs through the internal interface (`hazmat`, Algorithms 18-20) with M' built
//! here. External-interface cases also run through the public API whenever it supports the
//! case, so the crate's own M' encoding, context handling and pre-hash code are checked too.

mod common;

use common::{FixedRng, acvp_prehash, crate_prehash, hex, prehash_message, pure_message};
use serde_json::Value;
use slhsig::*;
use std::sync::OnceLock;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/acvp/{name}.json.gz", env!("CARGO_MANIFEST_DIR"));
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let reader = flate2::read::GzDecoder::new(std::io::BufReader::new(file));
    serde_json::from_reader(reader).expect("valid ACVP JSON")
}

fn doc(name: &'static str) -> &'static Value {
    static KEYGEN: OnceLock<Value> = OnceLock::new();
    static SIGGEN: OnceLock<Value> = OnceLock::new();
    static SIGVER: OnceLock<Value> = OnceLock::new();
    match name {
        "keyGen" => KEYGEN.get_or_init(|| load("keyGen")),
        "sigGen" => SIGGEN.get_or_init(|| load("sigGen")),
        "sigVer" => SIGVER.get_or_init(|| load("sigVer")),
        _ => unreachable!(),
    }
}

fn groups(name: &'static str, set: &'static str) -> impl Iterator<Item = &'static Value> {
    doc(name)["testGroups"].as_array().unwrap().iter().filter(move |g| g["parameterSet"] == set)
}

fn tests(group: &Value) -> &Vec<Value> {
    group["tests"].as_array().unwrap()
}

fn bytes(t: &Value, key: &str) -> Vec<u8> {
    hex(t[key].as_str().unwrap_or_else(|| panic!("missing {key}")))
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("missing {key}"))
}

/// M' for a test case, as the internal functions see it.
fn message_prime(interface: &str, prehash: &str, t: &Value) -> Vec<u8> {
    let msg = bytes(t, "message");
    match (interface, prehash) {
        ("internal", _) => msg,
        ("external", "pure") => pure_message(&bytes(t, "context"), &msg),
        ("external", "preHash") => {
            let (oid, digest) = acvp_prehash(text(t, "hashAlg"), &msg);
            prehash_message(&bytes(t, "context"), &oid, &digest)
        }
        other => panic!("unexpected test group kind {other:?}"),
    }
}

fn keygen<P: ParameterSet>() -> usize {
    let mut count = 0;
    for group in groups("keyGen", P::NAME) {
        for t in tests(group) {
            let id = &t["tcId"];
            let (sk, pk) = hazmat::keygen_internal::<P>(
                &bytes(t, "skSeed"),
                &bytes(t, "skPrf"),
                &bytes(t, "pkSeed"),
            )
            .unwrap();
            assert_eq!(sk.as_ref(), &bytes(t, "sk")[..], "{} keyGen tcId {id}: sk", P::NAME);
            assert_eq!(pk.as_ref(), &bytes(t, "pk")[..], "{} keyGen tcId {id}: pk", P::NAME);
            // The checked import recomputes the same PK.root.
            let key = SigningKey::<P>::from_slice(&bytes(t, "sk")).unwrap();
            assert_eq!(key.verifying_key().to_bytes().as_ref(), &bytes(t, "pk")[..]);
            count += 1;
        }
    }
    count
}

/// Signs an external-interface case through the public API, if the API supports it.
fn public_sign<P: ParameterSet>(t: &Value, prehash: &str, addrnd: Option<&[u8]>, expected: &[u8]) {
    let sk = bytes(t, "sk");
    let msg = bytes(t, "message");
    let ctx_bytes = bytes(t, "context");
    let ctx = Context::new(&ctx_bytes).unwrap();
    let id = &t["tcId"];

    let digest = if prehash == "preHash" {
        let Some(alg) = crate_prehash(text(t, "hashAlg")) else {
            return; // A hash this crate does not offer; covered by the internal path.
        };
        if !alg.suits_category(P::CATEGORY) {
            let mut key = SigningKey::<P>::from_slice(&sk).unwrap();
            assert_eq!(key.set_usage(KeyUsage::PreHash(alg)), Err(Error::PreHashTooWeak));
            return;
        }
        Some(alg.digest(&msg))
    } else {
        None
    };
    let usage = match &digest {
        Some(d) => KeyUsage::PreHash(d.as_prehashed().alg()),
        None => KeyUsage::Pure,
    };

    let sig = match addrnd {
        None => {
            let mut key = SigningKey::<P, Deterministic>::from_slice(&sk).unwrap();
            key.set_usage(usage).unwrap();
            // The fault check never changes the output; it is tested in tests/api.rs.
            key.set_fault_check(FaultCheck::None);
            match &digest {
                Some(d) => key.sign_prehashed(d.as_prehashed(), ctx),
                None => key.sign(&msg, ctx),
            }
        }
        Some(addrnd) => {
            let mut key = SigningKey::<P, Hedged>::from_slice(&sk).unwrap();
            key.set_usage(usage).unwrap();
            // The fault check never changes the output; it is tested in tests/api.rs.
            key.set_fault_check(FaultCheck::None);
            let mut rng = FixedRng::new(addrnd);
            match &digest {
                Some(d) => key.try_sign_prehashed(&mut rng, d.as_prehashed(), ctx),
                None => key.try_sign(&mut rng, &msg, ctx),
            }
        }
    }
    .unwrap();
    assert_eq!(sig.as_bytes(), expected, "{} sigGen tcId {id}: public API", P::NAME);
}

fn siggen<P: ParameterSet>() -> usize {
    let mut count = 0;
    for group in groups("sigGen", P::NAME) {
        let interface = text(group, "signatureInterface");
        let prehash = text(group, "preHash");
        let deterministic = group["deterministic"].as_bool().unwrap();
        for t in tests(group) {
            let id = &t["tcId"];
            let expected = bytes(t, "signature");
            let addrnd = (!deterministic).then(|| bytes(t, "additionalRandomness"));
            let m_prime = message_prime(interface, prehash, t);
            let sig =
                hazmat::sign_internal::<P>(&bytes(t, "sk"), &m_prime, addrnd.as_deref()).unwrap();
            assert!(
                sig == expected,
                "{} sigGen tcId {id} ({interface}, {prehash}, deterministic={deterministic})",
                P::NAME
            );
            if interface == "external" {
                public_sign::<P>(t, prehash, addrnd.as_deref(), &expected);
            }
            count += 1;
        }
    }
    count
}

fn sigver<P: ParameterSet>() -> usize {
    let mut count = 0;
    for group in groups("sigVer", P::NAME) {
        let interface = text(group, "signatureInterface");
        let prehash = text(group, "preHash");
        for t in tests(group) {
            let id = &t["tcId"];
            let reason = text(t, "reason");
            let passed = t["testPassed"].as_bool().unwrap();
            let pk = bytes(t, "pk");
            let sig = bytes(t, "signature");
            let m_prime = message_prime(interface, prehash, t);
            assert_eq!(
                hazmat::verify_internal::<P>(&pk, &m_prime, &sig),
                passed,
                "{} sigVer tcId {id}: {reason}",
                P::NAME
            );
            if interface == "external" {
                let vk = VerifyingKey::<P>::from_slice(&pk).unwrap();
                let msg = bytes(t, "message");
                let ctx_bytes = bytes(t, "context");
                let ctx = Context::new(&ctx_bytes).unwrap();
                let api_result = if prehash == "pure" {
                    Some(vk.verify_bytes(&msg, ctx, &sig).is_ok())
                } else {
                    crate_prehash(text(t, "hashAlg"))
                        .filter(|alg| alg.suits_category(P::CATEGORY))
                        .map(|alg| {
                            let digest = alg.digest(&msg);
                            Signature::<P>::from_slice(&sig)
                                .map(|s| {
                                    vk.verify_prehashed(digest.as_prehashed(), ctx, &s).is_ok()
                                })
                                .unwrap_or(false)
                        })
                };
                if let Some(ok) = api_result {
                    assert_eq!(ok, passed, "{} sigVer tcId {id}: public API, {reason}", P::NAME);
                }
            }
            count += 1;
        }
    }
    count
}

macro_rules! acvp {
    ($($module:ident => $set:ty),* $(,)?) => {$(
        mod $module {
            use super::*;

            #[test]
            fn key_gen() {
                assert_eq!(keygen::<$set>(), 10);
            }

            #[test]
            fn sig_gen() {
                assert_eq!(siggen::<$set>(), 52);
            }

            #[test]
            fn sig_ver() {
                assert_eq!(sigver::<$set>(), 42);
            }
        }
    )*};
}

acvp!(
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
