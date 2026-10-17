//! WOTS+ one-time signatures (FIPS 205 Section 5, Algorithms 5-8).
//!
//! Every loop bound and chain length here is public: message digits come from public nodes
//! (an XMSS root or a FORS public key). Secret values are the PRF outputs (chain starts) and
//! the chain positions below the signed digit; they only ever enter hash inputs.

use crate::adrs::{Adrs, AdrsType};
use crate::encoding::{base_2b, to_byte};
use crate::hash::{ByteArray, HashSuite, TStream};
use crate::params::{MAX_LEN, NodeOf, ParameterSet, SeededOf, gen_len2};
use zeroize::Zeroize;

/// w = 2^lg_w (Equation 5.1), with lg_w = 4.
const W: u32 = 16;
const LG_W: u32 = 4;
/// len2 (Algorithm 1). It is 3 for lg_w = 4 and every approved n; `params` asserts this per set.
const LEN2: usize = gen_len2(16, LG_W as usize);

/// Algorithm 5: `chain(X, i, s, PK.seed, ADRS)`.
fn chain<P: ParameterSet>(
    seeded: &SeededOf<P>,
    x: NodeOf<P>,
    i: u32,
    s: u32,
    adrs: &mut Adrs,
) -> NodeOf<P> {
    // 1: tmp <- X
    let mut tmp = x;
    // 2: for j from i to i + s - 1 do
    for j in i..i + s {
        // 3: ADRS.setHashAddress(j)
        adrs.set_hash(j);
        // 4: tmp <- F(PK.seed, ADRS, tmp)
        tmp = P::Hash::f(seeded, adrs, &tmp);
    }
    // 6: return tmp
    tmp
}

/// Lines 1-7 of Algorithms 7 and 8: base-w digits of `m` followed by the checksum digits.
fn digits<P: ParameterSet>(m: &NodeOf<P>, out: &mut [u32; MAX_LEN]) {
    let len1 = 2 * P::N;
    // 2: msg <- base_2b(M, lg_w, len1)
    base_2b(m.as_ref(), LG_W, &mut out[..len1]);
    // 1, 3-5: csum <- sum over i of (w - 1 - msg[i])
    let mut csum: u32 = 0;
    for &digit in &out[..len1] {
        csum += W - 1 - digit;
    }
    // 6: csum <- csum << ((8 - ((len2 * lg_w) mod 8)) mod 8)
    csum <<= (8 - ((LEN2 as u32 * LG_W) % 8)) % 8;
    // 7: msg <- msg || base_2b(toByte(csum, ceil(len2 * lg_w / 8)), lg_w, len2)
    let mut csum_bytes = [0u8; (LEN2 * LG_W as usize).div_ceil(8)];
    to_byte(u64::from(csum), &mut csum_bytes);
    base_2b(&csum_bytes, LG_W, &mut out[len1..len1 + LEN2]);
}

/// The key-generation and public-key-compression addresses derived from a WOTS_HASH address.
fn derived_addresses(adrs: &Adrs) -> (Adrs, Adrs) {
    // skADRS <- ADRS; setTypeAndClear(WOTS_PRF); setKeyPairAddress(ADRS.getKeyPairAddress())
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(AdrsType::WotsPrf);
    sk_adrs.set_key_pair(adrs.key_pair());
    // wotspkADRS <- ADRS; setTypeAndClear(WOTS_PK); setKeyPairAddress(ADRS.getKeyPairAddress())
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(AdrsType::WotsPk);
    pk_adrs.set_key_pair(adrs.key_pair());
    (sk_adrs, pk_adrs)
}

/// Algorithm 6: `wots_pkGen(SK.seed, PK.seed, ADRS)`. The chain ends are streamed into T_len.
pub(crate) fn pk_gen<P: ParameterSet>(
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    adrs: &Adrs,
) -> NodeOf<P> {
    let mut adrs = *adrs;
    // 1-3, 10-12: skADRS and wotspkADRS. setTypeAndClear zeroes the chain address, so deriving
    // wotspkADRS before the loop gives the same bytes as deriving it after.
    let (mut sk_adrs, pk_adrs) = derived_addresses(&adrs);
    let mut t = P::Hash::t_begin(seeded, &pk_adrs);
    // 4: for i from 0 to len - 1 do
    for i in 0..P::LEN as u32 {
        // 5-6: skADRS.setChainAddress(i); sk <- PRF(PK.seed, SK.seed, skADRS)
        sk_adrs.set_chain(i);
        let mut sk = P::Hash::prf(seeded, &sk_adrs, sk_seed);
        // 7-8: ADRS.setChainAddress(i); tmp[i] <- chain(sk, 0, w - 1, PK.seed, ADRS)
        adrs.set_chain(i);
        let end = chain::<P>(seeded, sk, 0, W - 1, &mut adrs);
        sk.zeroize();
        t.absorb(&end);
    }
    // 13: pk <- T_len(PK.seed, wotspkADRS, tmp)
    t.finish()
}

/// Algorithm 7: `wots_sign(M, SK.seed, PK.seed, ADRS)`. Writes len * n bytes to `out`.
pub(crate) fn sign<P: ParameterSet>(
    m: &NodeOf<P>,
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    adrs: &Adrs,
    out: &mut [u8],
) {
    debug_assert_eq!(out.len(), P::LEN * P::N);
    let mut adrs = *adrs;
    // 1-7: message and checksum digits
    let mut msg = [0u32; MAX_LEN];
    digits::<P>(m, &mut msg);
    // 8-10: skADRS
    let (mut sk_adrs, _) = derived_addresses(&adrs);
    // 11: for i from 0 to len - 1 do
    for (i, sig_i) in out.chunks_exact_mut(P::N).enumerate() {
        let i32 = i as u32;
        // 12-13: skADRS.setChainAddress(i); sk <- PRF(PK.seed, SK.seed, skADRS)
        sk_adrs.set_chain(i32);
        let mut sk = P::Hash::prf(seeded, &sk_adrs, sk_seed);
        // 14-15: ADRS.setChainAddress(i); sig[i] <- chain(sk, 0, msg[i], PK.seed, ADRS)
        adrs.set_chain(i32);
        let node = chain::<P>(seeded, sk, 0, msg[i], &mut adrs);
        sk.zeroize();
        sig_i.copy_from_slice(node.as_ref());
    }
}

/// Algorithm 8: `wots_pkFromSig(sig, M, PK.seed, ADRS)`.
pub(crate) fn pk_from_sig<P: ParameterSet>(
    sig: &[u8],
    m: &NodeOf<P>,
    seeded: &SeededOf<P>,
    adrs: &Adrs,
) -> NodeOf<P> {
    debug_assert_eq!(sig.len(), P::LEN * P::N);
    let mut adrs = *adrs;
    // 1-7: message and checksum digits
    let mut msg = [0u32; MAX_LEN];
    digits::<P>(m, &mut msg);
    // 12-14: wotspkADRS (derived early; see pk_gen)
    let (_, pk_adrs) = derived_addresses(&adrs);
    let mut t = P::Hash::t_begin(seeded, &pk_adrs);
    // 8: for i from 0 to len - 1 do
    for (i, sig_i) in sig.chunks_exact(P::N).enumerate() {
        // 9: ADRS.setChainAddress(i)
        adrs.set_chain(i as u32);
        // 10: tmp[i] <- chain(sig[i], msg[i], w - 1 - msg[i], PK.seed, ADRS)
        let start = NodeOf::<P>::copy_from(sig_i);
        let end = chain::<P>(seeded, start, msg[i], W - 1 - msg[i], &mut adrs);
        t.absorb(&end);
    }
    // 15: pk_sig <- T_len(PK.seed, wotspkADRS, tmp)
    t.finish()
}
