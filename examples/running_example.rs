//! Prints the running example used in docs/slides: an SLH-DSA-SHAKE-128f key pair from fixed
//! seeds and a deterministic signature, as JSON. `cargo run --example running_example`.

use slhsig::{Context, Deterministic, ParameterSet, Shake128f, SigningKey};

/// Replays the fixed seed bytes SK.seed || SK.prf || PK.seed.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let seeds: Vec<u8> = (0u8..48).collect(); // SK.seed = 00..0f, SK.prf = 10..1f, PK.seed = 20..2f
    let sk = SigningKey::<Shake128f, Deterministic>::try_generate(&mut Seeds(&seeds)).unwrap();
    let ctx = b"slides";
    let msg = b"Hello, FIPS 205!";
    let sig = sk.sign(msg, Context::new(ctx).unwrap()).unwrap();
    println!(
        "{{\"set\":\"{}\",\"sk\":\"{}\",\"pk\":\"{}\",\"msg\":\"{}\",\"ctx\":\"{}\",\"sig\":\"{}\"}}",
        Shake128f::NAME,
        hex(sk.to_bytes().as_ref()),
        hex(sk.verifying_key().to_bytes().as_ref()),
        hex(msg),
        hex(ctx),
        hex(sig.as_bytes()),
    );
}
