//! SLH-DSA internal functions (FIPS 205 Section 9, Algorithms 18-20).

use crate::adrs::{Adrs, AdrsType};
use crate::encoding::{low_bits_mask, to_int};
use crate::hash::{ByteArray, HashSuite, MsgParts};
use crate::params::{MAX_M, NodeOf, ParameterSet, SeededOf};
use crate::{fors, hypertree, xmss};

/// Byte length of SIG_FORS, `k * (1 + a) * n`.
const fn fors_sig_len<P: ParameterSet>() -> usize {
    P::K * (1 + P::A) * P::N
}

/// Lines 6-10 of Algorithm 19 (and 9-13 of Algorithm 20): split the m-byte digest into md,
/// idx_tree and idx_leaf. `low_bits_mask` handles h - h/d = 64 (the 256f sets).
fn split_digest<P: ParameterSet>(digest: &[u8]) -> (&[u8], u64, u32) {
    let md_len = (P::K * P::A).div_ceil(8);
    let tree_bits = P::H - P::HP;
    let tree_len = tree_bits.div_ceil(8);
    let leaf_len = P::HP.div_ceil(8);
    debug_assert_eq!(digest.len(), md_len + tree_len + leaf_len);
    // 6: md <- digest[0 : ceil(k*a/8)]
    let md = &digest[..md_len];
    // 7, 9: idx_tree <- toInt(next ceil((h - h/d)/8) bytes) mod 2^(h - h/d)
    let idx_tree = to_int(&digest[md_len..md_len + tree_len]) & low_bits_mask(tree_bits);
    // 8, 10: idx_leaf <- toInt(next ceil(h/(8d)) bytes) mod 2^(h/d)
    let idx_leaf = to_int(&digest[md_len + tree_len..]) & low_bits_mask(P::HP);
    (md, idx_tree, idx_leaf as u32)
}

/// Algorithm 18: `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`. Returns PK.root; the
/// caller assembles the keys.
pub(crate) fn keygen_internal<P: ParameterSet>(
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
) -> NodeOf<P> {
    // 1-2: ADRS <- toByte(0, 32); ADRS.setLayerAddress(d - 1)
    let mut adrs = Adrs::new();
    adrs.set_layer(P::D as u32 - 1);
    // 3: PK.root <- xmss_node(SK.seed, 0, h', PK.seed, ADRS)
    xmss::node::<P>(sk_seed, seeded, 0, P::HP as u32, &mut adrs)
}

/// The key material Algorithm 19 needs.
pub(crate) struct SignInputs<'a, P: ParameterSet> {
    pub(crate) sk_seed: &'a NodeOf<P>,
    pub(crate) sk_prf: &'a NodeOf<P>,
    pub(crate) pk_seed: &'a NodeOf<P>,
    pub(crate) pk_root: &'a NodeOf<P>,
    pub(crate) seeded: &'a SeededOf<P>,
}

/// Algorithm 19: `slh_sign_internal(M, SK, addrnd)`. `addrnd = None` is the deterministic
/// variant. Writes exactly `P::SIG_BYTES` bytes to `out`.
pub(crate) fn sign_internal<P: ParameterSet>(
    msg: MsgParts<'_>,
    key: &SignInputs<'_, P>,
    addrnd: Option<&NodeOf<P>>,
    out: &mut [u8],
) {
    assert_eq!(out.len(), P::SIG_BYTES);
    let n = P::N;
    // 2: opt_rand <- addrnd (substitute PK.seed for the deterministic variant)
    let opt_rand = addrnd.unwrap_or(key.pk_seed);
    // 3-4: R <- PRF_msg(SK.prf, opt_rand, M); SIG <- R
    let r = P::Hash::prf_msg(key.sk_prf, opt_rand, msg);
    let (r_out, rest) = out.split_at_mut(n);
    r_out.copy_from_slice(r.as_ref());
    // 5: digest <- H_msg(R, PK.seed, PK.root, M)
    let mut digest = [0u8; MAX_M];
    P::Hash::h_msg(&r, key.pk_seed, key.pk_root, msg, &mut digest[..P::M]);
    // 6-10: md, idx_tree, idx_leaf
    let (md, idx_tree, idx_leaf) = split_digest::<P>(&digest[..P::M]);
    // 11-13: ADRS.setTreeAddress(idx_tree); setTypeAndClear(FORS_TREE); setKeyPairAddress(idx_leaf)
    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(AdrsType::ForsTree);
    adrs.set_key_pair(idx_leaf);
    // 14-15: SIG_FORS <- fors_sign(md, SK.seed, PK.seed, ADRS); SIG <- SIG || SIG_FORS
    let (fors_out, ht_out) = rest.split_at_mut(fors_sig_len::<P>());
    fors::sign::<P>(md, key.sk_seed, key.seeded, &mut adrs, fors_out);
    // 16: PK_FORS <- fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
    let pk_fors = fors::pk_from_sig::<P>(fors_out, md, key.seeded, &mut adrs);
    // 17-18: SIG_HT <- ht_sign(PK_FORS, SK.seed, PK.seed, idx_tree, idx_leaf); SIG <- SIG || SIG_HT
    hypertree::sign::<P>(&pk_fors, key.sk_seed, key.seeded, idx_tree, idx_leaf, ht_out);
}

/// Algorithm 20: `slh_verify_internal(M, SIG, PK)`.
pub(crate) fn verify_internal<P: ParameterSet>(
    msg: MsgParts<'_>,
    sig: &[u8],
    pk_seed: &NodeOf<P>,
    pk_root: &NodeOf<P>,
    seeded: &SeededOf<P>,
) -> bool {
    // 1-3: if |SIG| != (1 + k(1 + a) + h + d * len) * n then return false
    if sig.len() != P::SIG_BYTES {
        return false;
    }
    let n = P::N;
    // 5-7: R, SIG_FORS, SIG_HT
    let (r, rest) = sig.split_at(n);
    let (sig_fors, sig_ht) = rest.split_at(fors_sig_len::<P>());
    let r = NodeOf::<P>::copy_from(r);
    // 8: digest <- H_msg(R, PK.seed, PK.root, M)
    let mut digest = [0u8; MAX_M];
    P::Hash::h_msg(&r, pk_seed, pk_root, msg, &mut digest[..P::M]);
    // 9-13: md, idx_tree, idx_leaf
    let (md, idx_tree, idx_leaf) = split_digest::<P>(&digest[..P::M]);
    // 14-16: ADRS.setTreeAddress(idx_tree); setTypeAndClear(FORS_TREE); setKeyPairAddress(idx_leaf)
    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    adrs.set_type_and_clear(AdrsType::ForsTree);
    adrs.set_key_pair(idx_leaf);
    // 17: PK_FORS <- fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
    let pk_fors = fors::pk_from_sig::<P>(sig_fors, md, seeded, &mut adrs);
    // 18: return ht_verify(PK_FORS, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
    hypertree::verify::<P>(&pk_fors, sig_ht, seeded, idx_tree, idx_leaf, pk_root)
}

#[cfg(test)]
mod tests {
    use crate::encoding::low_bits_mask;

    // The 256f sets need all 64 bits of idx_tree: h - h/d = 68 - 4.
    #[test]
    fn tree_index_mask_widths() {
        for (h, hp) in [(63usize, 9usize), (66, 3), (64, 8), (68, 4)] {
            let bits = h - hp;
            let mask = low_bits_mask(bits);
            assert_eq!(mask.count_ones() as usize, bits);
        }
    }
}
