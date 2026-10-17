//! Every parser must reject or accept arbitrary bytes without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use slhsig::*;

fn parse<P: ParameterSet>(data: &[u8]) {
    let _ = VerifyingKey::<P>::from_slice(data);
    let _ = Signature::<P>::from_slice(data);
    // The checked import recomputes PK.root, so only try it on correctly sized inputs.
    if data.len() == P::SK_BYTES {
        let _ = SigningKey::<P>::from_slice(data);
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = Context::new(data);
    for alg in [PreHash::Sha256, PreHash::Sha512, PreHash::Shake128, PreHash::Shake256] {
        let _ = PreHashed::new(alg, data);
    }
    parse::<Sha2_128f>(data);
    parse::<Shake128f>(data);
    parse::<Sha2_192f>(data);
    parse::<Shake256f>(data);
});
