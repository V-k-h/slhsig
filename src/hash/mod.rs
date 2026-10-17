//! Hash suites: the six functions H_msg, PRF, PRF_msg, F, H and T_l (FIPS 205 Section 11).
//!
//! The hash function is chosen per function, never per parameter set. That matters for the
//! SHA2 category 3 and 5 sets, which mix SHA-256 (PRF, F) and SHA-512 (H, T_l, PRF_msg, H_msg).
//!
//! The traits and types here are `pub` but unnameable outside the crate: they appear in the
//! bounds of the public, sealed `ParameterSet` trait, which requires nominal `pub` visibility.
#![allow(unreachable_pub)]

#[cfg(any(
    feature = "sha2-128s",
    feature = "sha2-128f",
    feature = "sha2-192s",
    feature = "sha2-192f",
    feature = "sha2-256s",
    feature = "sha2-256f"
))]
pub(crate) mod sha2;
#[cfg(any(
    feature = "shake-128s",
    feature = "shake-128f",
    feature = "shake-192s",
    feature = "shake-192f",
    feature = "shake-256s",
    feature = "shake-256f"
))]
pub(crate) mod shake;

use crate::adrs::Adrs;
use zeroize::Zeroize;

/// A fixed-size byte array: an n-byte node, or an encoded key.
///
/// Implemented only for `[u8; L]`. Sealed: downstream crates cannot implement it.
pub trait ByteArray:
    Copy
    + AsRef<[u8]>
    + AsMut<[u8]>
    + for<'a> TryFrom<&'a [u8]>
    + Eq
    + Send
    + Sync
    + Zeroize
    + crate::params::sealed::Sealed
    + 'static
{
    /// Length in bytes.
    const LEN: usize;
    /// An all-zero array.
    fn zeroed() -> Self;
    /// Copies an array out of `bytes`, which must be exactly `LEN` bytes long.
    fn copy_from(bytes: &[u8]) -> Self {
        let mut out = Self::zeroed();
        out.as_mut().copy_from_slice(bytes);
        out
    }
}

impl<const L: usize> crate::params::sealed::Sealed for [u8; L] {}

impl<const L: usize> ByteArray for [u8; L] {
    const LEN: usize = L;
    fn zeroed() -> Self {
        [0u8; L]
    }
}

/// The message M' passed to the internal functions, as borrowed pieces.
///
/// The pure encoding is `[0x00, len(ctx)] || ctx || M`; the pre-hash encoding is
/// `[0x01, len(ctx)] || ctx || OID || PH(M)`. Holding the pieces avoids copying M.
#[derive(Clone, Copy)]
pub struct MsgParts<'a>(pub(crate) &'a [&'a [u8]]);

impl MsgParts<'_> {
    pub(crate) fn for_each(&self, mut f: impl FnMut(&[u8])) {
        for part in self.0 {
            f(part);
        }
    }
}

/// Incremental input to T_l: the l nodes are fed one at a time, so no array of l nodes is built.
pub trait TStream<N> {
    fn absorb(&mut self, node: &N);
    fn finish(self) -> N;
}

/// One hash-function instantiation from FIPS 205 Section 11.
pub trait HashSuite: Send + Sync + 'static {
    /// An n-byte string.
    type Node: ByteArray;
    /// Hasher state with PK.seed (and its padding, for SHA2) already absorbed. PK.seed is public.
    #[doc(hidden)]
    type Seeded: Clone + Send + Sync;
    #[doc(hidden)]
    type T: TStream<Self::Node>;

    #[doc(hidden)]
    fn seed(pk_seed: &Self::Node) -> Self::Seeded;
    /// `PRF(PK.seed, SK.seed, ADRS)`.
    #[doc(hidden)]
    fn prf(s: &Self::Seeded, adrs: &Adrs, sk_seed: &Self::Node) -> Self::Node;
    /// `F(PK.seed, ADRS, M1)`.
    #[doc(hidden)]
    fn f(s: &Self::Seeded, adrs: &Adrs, m1: &Self::Node) -> Self::Node;
    /// `H(PK.seed, ADRS, left || right)`.
    #[doc(hidden)]
    fn h(s: &Self::Seeded, adrs: &Adrs, left: &Self::Node, right: &Self::Node) -> Self::Node;
    /// Starts `T_l(PK.seed, ADRS, M_l)`; the caller absorbs the l nodes.
    #[doc(hidden)]
    fn t_begin(s: &Self::Seeded, adrs: &Adrs) -> Self::T;
    /// `PRF_msg(SK.prf, opt_rand, M)`.
    #[doc(hidden)]
    fn prf_msg(sk_prf: &Self::Node, opt_rand: &Self::Node, msg: MsgParts<'_>) -> Self::Node;
    /// `H_msg(R, PK.seed, PK.root, M)`, writing `out.len()` (= m) bytes.
    #[doc(hidden)]
    fn h_msg(
        r: &Self::Node,
        pk_seed: &Self::Node,
        pk_root: &Self::Node,
        msg: MsgParts<'_>,
        out: &mut [u8],
    );
}
