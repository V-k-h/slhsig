//! FORS few-time signatures (FIPS 205 Section 8, Algorithms 14-17).
//!
//! The FORS indices come from the message digest, which the verifier recomputes, so they are
//! public. Secret values are the PRF outputs (leaf secrets) of the unrevealed leaves.

use crate::adrs::{Adrs, AdrsType};
use crate::encoding::base_2b;
use crate::hash::{ByteArray, HashSuite, TStream};
use crate::params::{MAX_A, MAX_K, NodeOf, ParameterSet, SeededOf};
use zeroize::Zeroize;

/// Algorithm 14: `fors_skGen(SK.seed, PK.seed, ADRS, idx)`.
fn sk_gen<P: ParameterSet>(
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    adrs: &Adrs,
    idx: u32,
) -> NodeOf<P> {
    // 1-4: skADRS <- ADRS; setTypeAndClear(FORS_PRF); setKeyPairAddress(...); setTreeIndex(idx)
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(AdrsType::ForsPrf);
    sk_adrs.set_key_pair(adrs.key_pair());
    sk_adrs.set_tree_index(idx);
    // 5: return PRF(PK.seed, SK.seed, skADRS)
    P::Hash::prf(seeded, &sk_adrs, sk_seed)
}

/// Algorithm 15: `fors_node(SK.seed, i, z, PK.seed, ADRS)`, computed iteratively as in
/// `xmss::node`. The address keeps type FORS_TREE and its key pair address throughout.
fn node<P: ParameterSet>(
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    i: u32,
    z: u32,
    adrs: &mut Adrs,
) -> NodeOf<P> {
    debug_assert!(z as usize <= P::A);
    let mut stack = [NodeOf::<P>::zeroed(); MAX_A + 1];
    let mut heights = [0u32; MAX_A + 1];
    let mut top = 0usize;

    let first = i << z;
    for leaf in first..first + (1u32 << z) {
        // 2: sk <- fors_skGen(SK.seed, PK.seed, ADRS, i)
        let mut sk = sk_gen::<P>(sk_seed, seeded, adrs, leaf);
        // 3-5: ADRS.setTreeHeight(0); ADRS.setTreeIndex(i); node <- F(PK.seed, ADRS, sk)
        adrs.set_tree_height(0);
        adrs.set_tree_index(leaf);
        let mut current = P::Hash::f(seeded, adrs, &sk);
        sk.zeroize();
        let mut height = 0u32;
        let mut index = leaf;
        while top > 0 && heights[top - 1] == height {
            top -= 1;
            // 9-11: ADRS.setTreeHeight(z); ADRS.setTreeIndex(i); node <- H(lnode || rnode)
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

/// `indices <- base_2b(md, a, k)`.
fn indices<P: ParameterSet>(md: &[u8]) -> [u32; MAX_K] {
    let mut out = [0u32; MAX_K];
    base_2b(md, P::A as u32, &mut out[..P::K]);
    out
}

/// Algorithm 16: `fors_sign(md, SK.seed, PK.seed, ADRS)`. Writes `k * (1 + a) * n` bytes.
pub(crate) fn sign<P: ParameterSet>(
    md: &[u8],
    sk_seed: &NodeOf<P>,
    seeded: &SeededOf<P>,
    adrs: &mut Adrs,
    out: &mut [u8],
) {
    debug_assert_eq!(out.len(), P::K * (1 + P::A) * P::N);
    let a = P::A as u32;
    // 2: indices <- base_2b(md, a, k)
    let indices = indices::<P>(md);
    // 3: for i from 0 to k - 1 do
    for (i, tree_out) in out.chunks_exact_mut((1 + P::A) * P::N).enumerate() {
        let i32 = i as u32;
        let (sk_out, auth_out) = tree_out.split_at_mut(P::N);
        // 4: SIG_FORS <- SIG_FORS || fors_skGen(SK.seed, PK.seed, ADRS, i * 2^a + indices[i])
        let mut sk = sk_gen::<P>(sk_seed, seeded, adrs, (i32 << a) + indices[i]);
        sk_out.copy_from_slice(sk.as_ref());
        sk.zeroize();
        // 5: for j from 0 to a - 1 do
        for (j, auth_j) in auth_out.chunks_exact_mut(P::N).enumerate() {
            let j = j as u32;
            // 6: s <- floor(indices[i] / 2^j) xor 1
            let s = (indices[i] >> j) ^ 1;
            // 7: AUTH[j] <- fors_node(SK.seed, i * 2^(a - j) + s, j, PK.seed, ADRS)
            let auth = node::<P>(sk_seed, seeded, (i32 << (a - j)) + s, j, adrs);
            auth_j.copy_from_slice(auth.as_ref());
        }
    }
}

/// Algorithm 17: `fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)`. Roots are streamed into T_k.
pub(crate) fn pk_from_sig<P: ParameterSet>(
    sig_fors: &[u8],
    md: &[u8],
    seeded: &SeededOf<P>,
    adrs: &mut Adrs,
) -> NodeOf<P> {
    debug_assert_eq!(sig_fors.len(), P::K * (1 + P::A) * P::N);
    let a = P::A as u32;
    // 1: indices <- base_2b(md, a, k)
    let indices = indices::<P>(md);
    // 21-23: forspkADRS. setTypeAndClear clears tree height and index, so deriving it before the
    // loop gives the same bytes as deriving it after.
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(AdrsType::ForsRoots);
    pk_adrs.set_key_pair(adrs.key_pair());
    let mut t = P::Hash::t_begin(seeded, &pk_adrs);
    // 2: for i from 0 to k - 1 do
    for (i, tree_sig) in sig_fors.chunks_exact((1 + P::A) * P::N).enumerate() {
        let i32 = i as u32;
        // 3: sk <- SIG_FORS.getSK(i)
        let (sk, auth) = tree_sig.split_at(P::N);
        let sk = NodeOf::<P>::copy_from(sk);
        // 4-6: ADRS.setTreeHeight(0); ADRS.setTreeIndex(i * 2^a + indices[i]); node[0] <- F(sk)
        adrs.set_tree_height(0);
        adrs.set_tree_index((i32 << a) + indices[i]);
        let mut node = P::Hash::f(seeded, adrs, &sk);
        // 7: auth <- SIG_FORS.getAUTH(i); 8: for j from 0 to a - 1 do
        for (j, auth_j) in auth.chunks_exact(P::N).enumerate() {
            let j = j as u32;
            let auth_j = NodeOf::<P>::copy_from(auth_j);
            // 9: ADRS.setTreeHeight(j + 1)
            adrs.set_tree_height(j + 1);
            if (indices[i] >> j) & 1 == 0 {
                // 11-12: setTreeIndex(getTreeIndex() / 2); node[1] <- H(node[0] || auth[j])
                adrs.set_tree_index(adrs.tree_index() / 2);
                node = P::Hash::h(seeded, adrs, &node, &auth_j);
            } else {
                // 14-15: setTreeIndex((getTreeIndex() - 1) / 2); node[1] <- H(auth[j] || node[0])
                adrs.set_tree_index((adrs.tree_index() - 1) / 2);
                node = P::Hash::h(seeded, adrs, &auth_j, &node);
            }
        }
        // 19: root[i] <- node[0]
        t.absorb(&node);
    }
    // 24: pk <- T_k(PK.seed, forspkADRS, root)
    t.finish()
}
