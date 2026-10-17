//! The SLH-DSA hypertree (FIPS 205 Section 7, Algorithms 12-13).

use crate::adrs::Adrs;
use crate::encoding::low_bits_mask;
use crate::params::{NodeOf, ParameterSet, SeededOf};
use crate::xmss;

/// Length in bytes of one XMSS signature, `(h' + len) * n`.
const fn xmss_sig_len<P: ParameterSet>() -> usize {
    (P::HP + P::LEN) * P::N
}

/// Algorithm 12: `ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)`.
/// Writes `d * (h' + len) * n` bytes to `out`.
pub(crate) fn sign<P: ParameterSet>(
    m: &NodeOf<P>,
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    mut idx_tree: u64,
    mut idx_leaf: u32,
    out: &mut [u8],
) {
    debug_assert_eq!(out.len(), P::D * xmss_sig_len::<P>());
    let mut layers = out.chunks_exact_mut(xmss_sig_len::<P>());
    // 1-2: ADRS <- toByte(0, 32); ADRS.setTreeAddress(idx_tree)
    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    // 3-4: SIG_tmp <- xmss_sign(M, SK.seed, idx_leaf, PK.seed, ADRS); SIG_HT <- SIG_tmp
    let first = layers.next().expect("d >= 1");
    xmss::sign::<P>(m, sk_seed, seeded, idx_leaf, &mut adrs, first);
    // 5: root <- xmss_pkFromSig(idx_leaf, SIG_tmp, M, PK.seed, ADRS)
    let mut root = xmss::pk_from_sig::<P>(idx_leaf, first, m, seeded, &mut adrs);
    // 6: for j from 1 to d - 1 do
    for (j, layer) in (1..P::D).zip(layers) {
        // 7: idx_leaf <- idx_tree mod 2^h'
        idx_leaf = (idx_tree & low_bits_mask(P::HP)) as u32;
        // 8: idx_tree <- idx_tree >> h'
        idx_tree >>= P::HP;
        // 9-10: ADRS.setLayerAddress(j); ADRS.setTreeAddress(idx_tree)
        adrs.set_layer(j as u32);
        adrs.set_tree(idx_tree);
        // 11-12: SIG_tmp <- xmss_sign(root, SK.seed, idx_leaf, PK.seed, ADRS); append
        xmss::sign::<P>(&root, sk_seed, seeded, idx_leaf, &mut adrs, layer);
        // 13-14: if j < d - 1 then root <- xmss_pkFromSig(idx_leaf, SIG_tmp, root, PK.seed, ADRS)
        if j < P::D - 1 {
            root = xmss::pk_from_sig::<P>(idx_leaf, layer, &root, seeded, &mut adrs);
        }
    }
}

/// Algorithm 13: `ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)`.
pub(crate) fn verify<P: ParameterSet>(
    m: &NodeOf<P>,
    sig_ht: &[u8],
    seeded: &SeededOf<P>,
    mut idx_tree: u64,
    mut idx_leaf: u32,
    pk_root: &NodeOf<P>,
) -> bool {
    debug_assert_eq!(sig_ht.len(), P::D * xmss_sig_len::<P>());
    let mut layers = sig_ht.chunks_exact(xmss_sig_len::<P>());
    // 1-2: ADRS <- toByte(0, 32); ADRS.setTreeAddress(idx_tree)
    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    // 3-4: SIG_tmp <- SIG_HT.getXMSSSignature(0); node <- xmss_pkFromSig(...)
    let first = layers.next().expect("d >= 1");
    let mut node = xmss::pk_from_sig::<P>(idx_leaf, first, m, seeded, &mut adrs);
    // 5: for j from 1 to d - 1 do
    for (j, layer) in (1..P::D).zip(layers) {
        // 6-7: idx_leaf <- idx_tree mod 2^h'; idx_tree <- idx_tree >> h'
        idx_leaf = (idx_tree & low_bits_mask(P::HP)) as u32;
        idx_tree >>= P::HP;
        // 8-9: ADRS.setLayerAddress(j); ADRS.setTreeAddress(idx_tree)
        adrs.set_layer(j as u32);
        adrs.set_tree(idx_tree);
        // 10-11: SIG_tmp <- SIG_HT.getXMSSSignature(j); node <- xmss_pkFromSig(...)
        node = xmss::pk_from_sig::<P>(idx_leaf, layer, &node, seeded, &mut adrs);
    }
    // 13-17: return node = PK.root. Both values are public, so this need not be constant time.
    node == *pk_root
}
