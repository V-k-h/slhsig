//! Helpers shared by the integration tests.
#![allow(dead_code)]

use core::convert::Infallible;
use sha2::Digest;
use shake::digest::{ExtendableOutput, Update};

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// An RNG that replays fixed bytes: lets hedged signing reproduce a vector's `addrnd`.
pub struct FixedRng<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> FixedRng<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl rand_core::TryRng for FixedRng<'_> {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self.pos + dst.len();
        assert!(end <= self.bytes.len(), "FixedRng exhausted");
        dst.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng<'_> {}

/// An RNG that always fails, to exercise the entropy-failure paths.
pub struct FailingRng;

#[derive(Debug)]
pub struct RngDown;
impl core::fmt::Display for RngDown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("rng down")
    }
}
impl core::error::Error for RngDown {}

impl rand_core::TryRng for FailingRng {
    type Error = RngDown;
    fn try_next_u32(&mut self) -> Result<u32, RngDown> {
        Err(RngDown)
    }
    fn try_next_u64(&mut self) -> Result<u64, RngDown> {
        Err(RngDown)
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), RngDown> {
        Err(RngDown)
    }
}

impl rand_core::TryCryptoRng for FailingRng {}

/// DER-encoded OID and digest for every hash function ACVP uses with HashSLH-DSA. The OIDs
/// are the NIST hashAlgs arc 2.16.840.1.101.3.4.2.x.
pub fn acvp_prehash(alg: &str, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let arc: u8 = match alg {
        "SHA2-256" => 1,
        "SHA2-384" => 2,
        "SHA2-512" => 3,
        "SHA2-224" => 4,
        "SHA2-512/224" => 5,
        "SHA2-512/256" => 6,
        "SHA3-224" => 7,
        "SHA3-256" => 8,
        "SHA3-384" => 9,
        "SHA3-512" => 10,
        "SHAKE-128" => 11,
        "SHAKE-256" => 12,
        other => panic!("unknown ACVP hash algorithm {other}"),
    };
    let oid = vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc];
    let digest = match alg {
        "SHA2-224" => sha2::Sha224::digest(msg).to_vec(),
        "SHA2-256" => sha2::Sha256::digest(msg).to_vec(),
        "SHA2-384" => sha2::Sha384::digest(msg).to_vec(),
        "SHA2-512" => sha2::Sha512::digest(msg).to_vec(),
        "SHA2-512/224" => sha2::Sha512_224::digest(msg).to_vec(),
        "SHA2-512/256" => sha2::Sha512_256::digest(msg).to_vec(),
        "SHA3-224" => sha3::Sha3_224::digest(msg).to_vec(),
        "SHA3-256" => sha3::Sha3_256::digest(msg).to_vec(),
        "SHA3-384" => sha3::Sha3_384::digest(msg).to_vec(),
        "SHA3-512" => sha3::Sha3_512::digest(msg).to_vec(),
        "SHAKE-128" => {
            let mut h = shake::Shake128::default();
            h.update(msg);
            let mut out = vec![0u8; 32];
            h.finalize_xof_into(&mut out);
            out
        }
        "SHAKE-256" => {
            let mut h = shake::Shake256::default();
            h.update(msg);
            let mut out = vec![0u8; 64];
            h.finalize_xof_into(&mut out);
            out
        }
        _ => unreachable!(),
    };
    (oid, digest)
}

/// Maps an ACVP hash name onto this crate's [`slhsig::PreHash`], if supported.
pub fn crate_prehash(alg: &str) -> Option<slhsig::PreHash> {
    match alg {
        "SHA2-256" => Some(slhsig::PreHash::Sha256),
        "SHA2-512" => Some(slhsig::PreHash::Sha512),
        "SHAKE-128" => Some(slhsig::PreHash::Shake128),
        "SHAKE-256" => Some(slhsig::PreHash::Shake256),
        _ => None,
    }
}

/// M' for pure signing: `0x00 || len(ctx) || ctx || msg`.
pub fn pure_message(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = vec![0u8, ctx.len() as u8];
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    m
}

/// M' for pre-hash signing: `0x01 || len(ctx) || ctx || OID || PH(msg)`.
pub fn prehash_message(ctx: &[u8], oid: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut m = vec![1u8, ctx.len() as u8];
    m.extend_from_slice(ctx);
    m.extend_from_slice(oid);
    m.extend_from_slice(digest);
    m
}
