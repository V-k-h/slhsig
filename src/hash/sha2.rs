//! SLH-DSA using SHA2 (FIPS 205 Section 11.2).
//!
//! | Function | Category 1 (11.2.1)         | Categories 3 and 5 (11.2.2)  |
//! |----------|-----------------------------|------------------------------|
//! | PRF, F   | SHA-256, 64 - n pad         | SHA-256, 64 - n pad          |
//! | H, T_l   | SHA-256, 64 - n pad         | SHA-512, 128 - n pad         |
//! | PRF_msg  | HMAC-SHA-256                | HMAC-SHA-512                 |
//! | H_msg    | MGF1-SHA-256 over SHA-256   | MGF1-SHA-512 over SHA-512    |
//!
//! Every PK.seed-prefixed call hashes `PK.seed || toByte(0, B - n)`, which is exactly one
//! compression block of size B, so the state after that block is computed once per key
//! (`Seeded`) and cloned for each call. The pad length is fixed by the hash it belongs to.

use super::{ByteArray, HashSuite, MsgParts, TStream};
use crate::adrs::Adrs;
use sha2::Sha256;
#[cfg(any(
    test,
    feature = "sha2-192s",
    feature = "sha2-192f",
    feature = "sha2-256s",
    feature = "sha2-256f"
))]
use sha2::Sha512;
use sha2::digest::{Digest, Output};
use zeroize::Zeroize;

const SHA256_BLOCK: usize = 64;
const SHA512_BLOCK: usize = 128; // also the size of the zero-pad buffer in `seeded`

/// `Trunc_n(full)`.
fn trunc<const N: usize>(full: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

/// State after absorbing `PK.seed || toByte(0, block - n)`.
fn seeded<D: Digest>(pk_seed: &[u8], block: usize) -> D {
    const ZEROS: [u8; SHA512_BLOCK] = [0u8; SHA512_BLOCK];
    let mut h = D::new();
    Digest::update(&mut h, pk_seed);
    Digest::update(&mut h, &ZEROS[..block - pk_seed.len()]);
    h
}

/// HMAC (FIPS 198-1) for a key no longer than the block size `BS`.
pub(crate) fn hmac<D: Digest, const BS: usize>(key: &[u8], feed: impl FnOnce(&mut D)) -> Output<D> {
    debug_assert!(key.len() <= BS);
    let mut k0 = [0u8; BS];
    k0[..key.len()].copy_from_slice(key);

    let mut pad = [0u8; BS];
    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x36;
    }
    let mut inner = D::new();
    Digest::update(&mut inner, pad);
    feed(&mut inner);
    let inner_hash = inner.finalize();

    for (p, k) in pad.iter_mut().zip(k0.iter()) {
        *p = k ^ 0x5c;
    }
    let mut outer = D::new();
    Digest::update(&mut outer, pad);
    Digest::update(&mut outer, &inner_hash);
    k0.zeroize();
    pad.zeroize();
    outer.finalize()
}

/// MGF1 (RFC 8017 Appendix B.2.1) over the concatenation of `seed`, filling all of `out`.
pub(crate) fn mgf1<D: Digest>(seed: &[&[u8]], out: &mut [u8]) {
    for (counter, chunk) in out.chunks_mut(<D as Digest>::output_size()).enumerate() {
        let mut h = D::new();
        for part in seed {
            Digest::update(&mut h, part);
        }
        Digest::update(&mut h, (counter as u32).to_be_bytes());
        let block = h.finalize();
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// `MGF1-D(R || PK.seed || D(R || PK.seed || PK.root || M), m)`.
fn h_msg_sha2<D: Digest>(
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: MsgParts<'_>,
    out: &mut [u8],
) {
    let mut h = D::new();
    Digest::update(&mut h, r);
    Digest::update(&mut h, pk_seed);
    Digest::update(&mut h, pk_root);
    msg.for_each(|p| Digest::update(&mut h, p));
    let inner = h.finalize();
    mgf1::<D>(&[r, pk_seed, &inner], out);
}

/// `Trunc_n(D(seeded || ADRSc || parts...))`.
fn call<D: Digest + Clone, const N: usize>(s: &D, adrs: &Adrs, parts: &[&[u8]]) -> [u8; N] {
    let mut h = s.clone();
    Digest::update(&mut h, adrs.compressed());
    for part in parts {
        Digest::update(&mut h, part);
    }
    trunc::<N>(&h.finalize())
}

/// T_l in progress over hash `D`.
pub struct Sha2T<D, const N: usize>(D);

impl<D: Digest, const N: usize> TStream<[u8; N]> for Sha2T<D, N> {
    fn absorb(&mut self, node: &[u8; N]) {
        Digest::update(&mut self.0, node);
    }

    fn finish(self) -> [u8; N] {
        trunc::<N>(&self.0.finalize())
    }
}

#[cfg(any(feature = "sha2-128s", feature = "sha2-128f"))]
/// SHA2 for security category 1 (n = 16): SHA-256 throughout (Section 11.2.1).
#[derive(Debug)]
pub enum Sha2Cat1<const N: usize> {}

#[cfg(any(feature = "sha2-128s", feature = "sha2-128f"))]
impl<const N: usize> HashSuite for Sha2Cat1<N>
where
    [u8; N]: ByteArray,
{
    type Node = [u8; N];
    type Seeded = Sha256;
    type T = Sha2T<Sha256, N>;

    fn seed(pk_seed: &[u8; N]) -> Sha256 {
        seeded::<Sha256>(pk_seed, SHA256_BLOCK)
    }

    /// `Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || SK.seed))`.
    fn prf(s: &Sha256, adrs: &Adrs, sk_seed: &[u8; N]) -> [u8; N] {
        call::<Sha256, N>(s, adrs, &[sk_seed])
    }

    /// `Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || M1))`.
    fn f(s: &Sha256, adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
        call::<Sha256, N>(s, adrs, &[m1])
    }

    /// `Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || M2))`.
    fn h(s: &Sha256, adrs: &Adrs, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
        call::<Sha256, N>(s, adrs, &[left, right])
    }

    /// `Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || M_l))`.
    fn t_begin(s: &Sha256, adrs: &Adrs) -> Self::T {
        let mut h = s.clone();
        Digest::update(&mut h, adrs.compressed());
        Sha2T(h)
    }

    /// `Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M))`.
    fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], msg: MsgParts<'_>) -> [u8; N] {
        let mac = hmac::<Sha256, SHA256_BLOCK>(sk_prf, |h| {
            Digest::update(h, opt_rand);
            msg.for_each(|p| Digest::update(h, p));
        });
        trunc::<N>(&mac)
    }

    /// `MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)`.
    fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], msg: MsgParts<'_>, out: &mut [u8]) {
        h_msg_sha2::<Sha256>(r, pk_seed, pk_root, msg, out);
    }
}

#[cfg(any(
    feature = "sha2-192s",
    feature = "sha2-192f",
    feature = "sha2-256s",
    feature = "sha2-256f"
))]
/// Seeded states for categories 3 and 5: SHA-256 for PRF and F, SHA-512 for H and T_l.
#[derive(Clone)]
pub struct Sha2Cat35Seeded {
    s256: Sha256,
    s512: Sha512,
}

#[cfg(any(
    feature = "sha2-192s",
    feature = "sha2-192f",
    feature = "sha2-256s",
    feature = "sha2-256f"
))]
/// SHA2 for security categories 3 and 5 (n = 24, 32): Section 11.2.2.
#[derive(Debug)]
pub enum Sha2Cat35<const N: usize> {}

#[cfg(any(
    feature = "sha2-192s",
    feature = "sha2-192f",
    feature = "sha2-256s",
    feature = "sha2-256f"
))]
impl<const N: usize> HashSuite for Sha2Cat35<N>
where
    [u8; N]: ByteArray,
{
    type Node = [u8; N];
    type Seeded = Sha2Cat35Seeded;
    type T = Sha2T<Sha512, N>;

    fn seed(pk_seed: &[u8; N]) -> Sha2Cat35Seeded {
        Sha2Cat35Seeded {
            s256: seeded::<Sha256>(pk_seed, SHA256_BLOCK),
            s512: seeded::<Sha512>(pk_seed, SHA512_BLOCK),
        }
    }

    /// `Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || SK.seed))`.
    fn prf(s: &Sha2Cat35Seeded, adrs: &Adrs, sk_seed: &[u8; N]) -> [u8; N] {
        call::<Sha256, N>(&s.s256, adrs, &[sk_seed])
    }

    /// `Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || M1))`.
    fn f(s: &Sha2Cat35Seeded, adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
        call::<Sha256, N>(&s.s256, adrs, &[m1])
    }

    /// `Trunc_n(SHA-512(PK.seed || toByte(0, 128 - n) || ADRSc || M2))`.
    fn h(s: &Sha2Cat35Seeded, adrs: &Adrs, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
        call::<Sha512, N>(&s.s512, adrs, &[left, right])
    }

    /// `Trunc_n(SHA-512(PK.seed || toByte(0, 128 - n) || ADRSc || M_l))`.
    fn t_begin(s: &Sha2Cat35Seeded, adrs: &Adrs) -> Self::T {
        let mut h = s.s512.clone();
        Digest::update(&mut h, adrs.compressed());
        Sha2T(h)
    }

    /// `Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M))`.
    fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], msg: MsgParts<'_>) -> [u8; N] {
        let mac = hmac::<Sha512, SHA512_BLOCK>(sk_prf, |h| {
            Digest::update(h, opt_rand);
            msg.for_each(|p| Digest::update(h, p));
        });
        trunc::<N>(&mac)
    }

    /// `MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m)`.
    fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], msg: MsgParts<'_>, out: &mut [u8]) {
        h_msg_sha2::<Sha512>(r, pk_seed, pk_root, msg, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
    #[test]
    fn hmac_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let t256 = hmac::<Sha256, SHA256_BLOCK>(key, |h| Digest::update(h, data));
        assert_eq!(
            t256.as_slice(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        let t512 = hmac::<Sha512, SHA512_BLOCK>(key, |h| Digest::update(h, data));
        assert_eq!(
            t512.as_slice(),
            hex(concat!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ))
        );
    }

    // RFC 4231 test case 1: 20-byte key of 0x0b, data "Hi There". Split feeding must not matter.
    #[test]
    fn hmac_rfc4231_case1_split_input() {
        let key = [0x0bu8; 20];
        let t256 = hmac::<Sha256, SHA256_BLOCK>(&key, |h| {
            Digest::update(h, b"Hi ");
            Digest::update(h, b"There");
        });
        assert_eq!(
            t256.as_slice(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    // Expected values from Python hashlib:
    // b"".join(H(seed + c.to_bytes(4, "big")).digest() for c in range(..))[:len]
    #[test]
    fn mgf1_matches_python_reference() {
        let seed = b"slhsig mgf1 seed";
        let mut out256 = [0u8; 70];
        mgf1::<Sha256>(&[&seed[..4], &seed[4..]], &mut out256);
        assert_eq!(
            &out256[..],
            hex(concat!(
                "0ce11a10cb4de3f6a42f4c7eb55f520379a03a0303ac1bf48a60f362b6f9ad9e",
                "59b016f2ed8a4705c1074e54f1a7284ea6d9217add12c26ea56a63e9c81544f2",
                "01eb710f4189"
            ))
        );
        let mut out512 = [0u8; 100];
        mgf1::<Sha512>(&[seed], &mut out512);
        assert_eq!(
            &out512[..],
            hex(concat!(
                "123d70c313a1cdf12838c8dd4dbc6ecd7cb0463f1ac21dacf7e07b25d3e1abcb",
                "5b05d34431b44f836105064d726e77dae2e4fbbe772c3fd3a1ad139f5ab127da",
                "76ba25008adbcd53cb4b0742b15d58c30a9c33dc0dd778a0581fd1690f525ce7",
                "e29d573d"
            ))
        );
    }
}
