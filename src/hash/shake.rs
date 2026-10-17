//! SLH-DSA using SHAKE (FIPS 205 Section 11.1). Every function is SHAKE256 with the full
//! 32-byte ADRS.

use super::{ByteArray, HashSuite, MsgParts, TStream};
use crate::adrs::Adrs;
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update};

/// The SHAKE256 suite for n-byte nodes.
#[derive(Debug)]
pub enum ShakeSuite<const N: usize> {}

/// T_l in progress: `SHAKE256(PK.seed || ADRS || M_l, 8n)`.
pub struct ShakeT<const N: usize>(Shake256);

impl<const N: usize> TStream<[u8; N]> for ShakeT<N> {
    fn absorb(&mut self, node: &[u8; N]) {
        self.0.update(node);
    }

    fn finish(self) -> [u8; N] {
        let mut out = [0u8; N];
        self.0.finalize_xof_into(&mut out);
        out
    }
}

fn squeeze<const N: usize>(h: Shake256) -> [u8; N] {
    let mut out = [0u8; N];
    h.finalize_xof_into(&mut out);
    out
}

impl<const N: usize> HashSuite for ShakeSuite<N>
where
    [u8; N]: ByteArray,
{
    type Node = [u8; N];
    type Seeded = Shake256;
    type T = ShakeT<N>;

    fn seed(pk_seed: &[u8; N]) -> Shake256 {
        let mut h = Shake256::default();
        h.update(pk_seed);
        h
    }

    /// `PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)`.
    fn prf(s: &Shake256, adrs: &Adrs, sk_seed: &[u8; N]) -> [u8; N] {
        let mut h = s.clone();
        h.update(adrs.as_bytes());
        h.update(sk_seed);
        squeeze(h)
    }

    /// `F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1, 8n)`.
    fn f(s: &Shake256, adrs: &Adrs, m1: &[u8; N]) -> [u8; N] {
        let mut h = s.clone();
        h.update(adrs.as_bytes());
        h.update(m1);
        squeeze(h)
    }

    /// `H(PK.seed, ADRS, M2) = SHAKE256(PK.seed || ADRS || M2, 8n)`.
    fn h(s: &Shake256, adrs: &Adrs, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
        let mut h = s.clone();
        h.update(adrs.as_bytes());
        h.update(left);
        h.update(right);
        squeeze(h)
    }

    fn t_begin(s: &Shake256, adrs: &Adrs) -> ShakeT<N> {
        let mut h = s.clone();
        h.update(adrs.as_bytes());
        ShakeT(h)
    }

    /// `PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n)`.
    fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], msg: MsgParts<'_>) -> [u8; N] {
        let mut h = Shake256::default();
        h.update(sk_prf);
        h.update(opt_rand);
        msg.for_each(|p| h.update(p));
        squeeze(h)
    }

    /// `H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)`.
    fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], msg: MsgParts<'_>, out: &mut [u8]) {
        let mut h = Shake256::default();
        h.update(r);
        h.update(pk_seed);
        h.update(pk_root);
        msg.for_each(|p| h.update(p));
        h.finalize_xof_into(out);
    }
}
