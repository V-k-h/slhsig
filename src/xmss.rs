//! XMSS (FIPS 205 Section 6, Algorithms 9-11).

use crate::adrs::{Adrs, AdrsType};
use crate::hash::{ByteArray, HashSuite};
use crate::params::{MAX_HP, NodeOf, ParameterSet, SeededOf};
use crate::wots;

/// Algorithm 9: `xmss_node(SK.seed, i, z, PK.seed, ADRS)`.
///
/// Computed iteratively (treehash) instead of recursively. The leaves 2^z * i .. 2^z * (i+1)
/// are generated left to right, and two nodes at the same height are combined as soon as
/// both exist. Every H call gets the same (height, index) address and the same inputs as in
/// the recursive pseudocode, so the result is identical. The stack holds at most z + 1 nodes.
pub(crate) fn node<P: ParameterSet>(
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    i: u32,
    z: u32,
    adrs: &mut Adrs,
) -> NodeOf<P> {
    debug_assert!(z as usize <= P::HP);
    let mut stack = [NodeOf::<P>::zeroed(); MAX_HP + 1];
    let mut heights = [0u32; MAX_HP + 1];
    let mut top = 0usize;

    let first = i << z;
    for leaf in first..first + (1u32 << z) {
        // 2-4: ADRS.setTypeAndClear(WOTS_HASH); ADRS.setKeyPairAddress(i); wots_pkGen
        adrs.set_type_and_clear(AdrsType::WotsHash);
        adrs.set_key_pair(leaf);
        let mut current = wots::pk_gen::<P>(sk_seed, seeded, adrs);
        let mut height = 0u32;
        let mut index = leaf;
        while top > 0 && heights[top - 1] == height {
            top -= 1;
            // 8-11: ADRS.setTypeAndClear(TREE); setTreeHeight(z); setTreeIndex(i);
            //       node <- H(PK.seed, ADRS, lnode || rnode)
            adrs.set_type_and_clear(AdrsType::Tree);
            adrs.set_tree_height(height + 1);
            adrs.set_tree_index(index >> 1);
            current = P::Hash::h(seeded, adrs, &stack[top], &current);
            height += 1;
            index >>= 1;
        }
        stack[top] = current;
        heights[top] = height;
        top += 1;
    }
    debug_assert_eq!(top, 1);
    stack[0]
}

/// Algorithm 10: `xmss_sign(M, SK.seed, idx, PK.seed, ADRS)`.
/// Writes `(len + h') * n` bytes to `out`: the WOTS+ signature, then AUTH.
pub(crate) fn sign<P: ParameterSet>(
    m: &NodeOf<P>,
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    idx: u32,
    adrs: &mut Adrs,
    out: &mut [u8],
) {
    debug_assert_eq!(out.len(), (P::LEN + P::HP) * P::N);
    let (wots_out, auth_out) = out.split_at_mut(P::LEN * P::N);
    // 1: for j from 0 to h' - 1 do
    for (j, auth_j) in auth_out.chunks_exact_mut(P::N).enumerate() {
        let j = j as u32;
        // 2: k <- floor(idx / 2^j) xor 1
        let k = (idx >> j) ^ 1;
        // 3: AUTH[j] <- xmss_node(SK.seed, k, j, PK.seed, ADRS)
        let auth = node::<P>(sk_seed, seeded, k, j, adrs);
        auth_j.copy_from_slice(auth.as_ref());
    }
    // 5-6: ADRS.setTypeAndClear(WOTS_HASH); ADRS.setKeyPairAddress(idx)
    adrs.set_type_and_clear(AdrsType::WotsHash);
    adrs.set_key_pair(idx);
    // 7: sig <- wots_sign(M, SK.seed, PK.seed, ADRS)
    wots::sign::<P>(m, sk_seed, seeded, adrs, wots_out);
}

/// Algorithm 11: `xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)`.
pub(crate) fn pk_from_sig<P: ParameterSet>(
    idx: u32,
    sig_xmss: &[u8],
    m: &NodeOf<P>,
    seeded: &SeededOf<P>,
    adrs: &mut Adrs,
) -> NodeOf<P> {
    debug_assert_eq!(sig_xmss.len(), (P::LEN + P::HP) * P::N);
    // 1-2: ADRS.setTypeAndClear(WOTS_HASH); ADRS.setKeyPairAddress(idx)
    adrs.set_type_and_clear(AdrsType::WotsHash);
    adrs.set_key_pair(idx);
    // 3-4: sig <- SIG_XMSS[0 : len*n]; AUTH <- SIG_XMSS[len*n : (len + h')*n]
    let (sig, auth) = sig_xmss.split_at(P::LEN * P::N);
    // 5: node[0] <- wots_pkFromSig(sig, M, PK.seed, ADRS)
    let mut node = wots::pk_from_sig::<P>(sig, m, seeded, adrs);
    // 6-7: ADRS.setTypeAndClear(TREE); ADRS.setTreeIndex(idx)
    adrs.set_type_and_clear(AdrsType::Tree);
    adrs.set_tree_index(idx);
    // 8: for k from 0 to h' - 1 do
    for (k, auth_k) in auth.chunks_exact(P::N).enumerate() {
        let k = k as u32;
        let auth_k = NodeOf::<P>::copy_from(auth_k);
        // 9: ADRS.setTreeHeight(k + 1)
        adrs.set_tree_height(k + 1);
        if (idx >> k) & 1 == 0 {
            // 11-12: setTreeIndex(getTreeIndex() / 2); node[1] <- H(node[0] || AUTH[k])
            adrs.set_tree_index(adrs.tree_index() / 2);
            node = P::Hash::h(seeded, adrs, &node, &auth_k);
        } else {
            // 14-15: setTreeIndex((getTreeIndex() - 1) / 2); node[1] <- H(AUTH[k] || node[0])
            adrs.set_tree_index((adrs.tree_index() - 1) / 2);
            node = P::Hash::h(seeded, adrs, &auth_k, &node);
        }
    }
    // 19: return node[0]
    node
}
