//! The 12 approved parameter sets (FIPS 205 Section 11, Table 2).
//!
//! Each set is an uninhabited marker type. Every value below is checked at compile time
//! against the sizes it implies, so a mistyped Table 2 entry fails the build.

#[cfg(any(feature = "sha2-128s", feature = "sha2-128f"))]
use crate::hash::sha2::Sha2Cat1;
#[cfg(any(
    feature = "sha2-192s",
    feature = "sha2-192f",
    feature = "sha2-256s",
    feature = "sha2-256f"
))]
use crate::hash::sha2::Sha2Cat35;
#[cfg(any(
    feature = "shake-128s",
    feature = "shake-128f",
    feature = "shake-192s",
    feature = "shake-192f",
    feature = "shake-256s",
    feature = "shake-256f"
))]
use crate::hash::shake::ShakeSuite;
use crate::hash::{ByteArray, HashSuite};

pub(crate) mod sealed {
    /// Seals [`ParameterSet`](super::ParameterSet) and the internal byte-array trait.
    pub trait Sealed {}
}

/// Largest h' over the approved sets (SHA2/SHAKE-128s and -192s).
pub(crate) const MAX_HP: usize = 9;
/// Largest a (the 192s and 256s sets).
pub(crate) const MAX_A: usize = 14;
/// Largest k (the 256f sets).
pub(crate) const MAX_K: usize = 35;
/// Largest m (the 256f sets).
pub(crate) const MAX_M: usize = 49;
/// Largest WOTS+ len = 2n + 3 (n = 32).
pub(crate) const MAX_LEN: usize = 67;

/// An SLH-DSA parameter set from FIPS 205 Table 2. Sealed: only the 12 approved sets exist.
pub trait ParameterSet: sealed::Sealed + Sized + Send + Sync + 'static {
    #[doc(hidden)]
    type Hash: HashSuite;
    /// Encoded public key, `PK.seed || PK.root`.
    type PkBytes: ByteArray;
    /// Encoded secret key, `SK.seed || SK.prf || PK.seed || PK.root`.
    type SkBytes: ByteArray;

    /// The FIPS 205 name, for example `"SLH-DSA-SHAKE-128f"`.
    const NAME: &'static str;
    /// Claimed NIST security category: 1, 3 or 5.
    const CATEGORY: u8;
    /// Security parameter n, in bytes.
    const N: usize;
    /// Total hypertree height h.
    const H: usize;
    /// Number of hypertree layers d.
    const D: usize;
    /// Height h' = h / d of each XMSS tree.
    const HP: usize;
    /// FORS tree height a.
    const A: usize;
    /// Number of FORS trees k.
    const K: usize;
    /// H_msg output length m, in bytes.
    const M: usize;
    /// Winternitz parameter lg_w; 4 for every approved set.
    const LG_W: usize = 4;
    /// WOTS+ chain count len = 2n + 3 (for lg_w = 4).
    const LEN: usize = 2 * Self::N + 3;
    /// Public key size, 2n bytes.
    const PK_BYTES: usize = 2 * Self::N;
    /// Secret key size, 4n bytes.
    const SK_BYTES: usize = 4 * Self::N;
    /// Signature size, (1 + k(1 + a) + h + d * len) * n bytes (Algorithm 20, line 1).
    const SIG_BYTES: usize =
        (1 + Self::K * (1 + Self::A) + Self::H + Self::D * Self::LEN) * Self::N;
}

/// The n-byte node type of parameter set `P`.
pub(crate) type NodeOf<P> = <<P as ParameterSet>::Hash as HashSuite>::Node;
/// The PK.seed-seeded hasher state of parameter set `P`.
pub(crate) type SeededOf<P> = <<P as ParameterSet>::Hash as HashSuite>::Seeded;

/// Algorithm 1: `gen_len2(n, lg_w)`.
pub(crate) const fn gen_len2(n: usize, lg_w: usize) -> usize {
    // 1: w <- 2^lg_w
    let w = 1usize << lg_w;
    // 2: len1 <- floor((8n + lg_w - 1) / lg_w), that is, ceil(8n / lg_w)
    let len1 = (8 * n).div_ceil(lg_w);
    // 3: max_checksum <- len1 * (w - 1)
    let max_checksum = len1 * (w - 1);
    // 4-5: len2 <- 1; capacity <- w
    let mut len2 = 1;
    let mut capacity = w;
    // 6: while capacity <= max_checksum do
    while capacity <= max_checksum {
        // 7-8: len2 <- len2 + 1; capacity <- capacity * w
        len2 += 1;
        capacity *= w;
    }
    // 10: return len2
    len2
}

macro_rules! parameter_set {
    (
        $feature:literal, $ty:ident, $label:literal, $hash:ty, category = $cat:literal,
        n = $n:literal, h = $h:literal, d = $d:literal, hp = $hp:literal,
        a = $a:literal, k = $k:literal, m = $m:literal, sig = $sig:literal
    ) => {
        #[doc = concat!("`", $label, "`: FIPS 205 Table 2, security category ", stringify!($cat), ", ", stringify!($sig), "-byte signatures.")]
        #[cfg(feature = $feature)]
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $ty {}

        #[cfg(feature = $feature)]
        impl sealed::Sealed for $ty {}

        #[cfg(feature = $feature)]
        impl ParameterSet for $ty {
            type Hash = $hash;
            type PkBytes = [u8; 2 * $n];
            type SkBytes = [u8; 4 * $n];
            const NAME: &'static str = $label;
            const CATEGORY: u8 = $cat;
            const N: usize = $n;
            const H: usize = $h;
            const D: usize = $d;
            const HP: usize = $hp;
            const A: usize = $a;
            const K: usize = $k;
            const M: usize = $m;
        }

        #[cfg(feature = $feature)]
        const _: () = {
            type P = $ty;
            assert!(<P as ParameterSet>::SIG_BYTES == $sig, "signature size disagrees with Table 2");
            assert!($h == $d * $hp, "h must equal d * h'");
            assert!(
                $m == ($k * $a + 7) / 8 + ($h - $hp + 7) / 8 + ($hp + 7) / 8,
                "m must equal ceil(k*a/8) + ceil((h - h/d)/8) + ceil(h/(8d))"
            );
            assert!(<<$hash as HashSuite>::Node as ByteArray>::LEN == $n, "hash node size must be n");
            assert!(<P as ParameterSet>::LG_W == 4 && gen_len2($n, 4) == 3, "len2 must be 3");
            assert!(<P as ParameterSet>::LEN <= MAX_LEN);
            assert!($hp <= MAX_HP && $a <= MAX_A && $k <= MAX_K && $m <= MAX_M);
            assert!($h - $hp <= 64, "idx_tree must fit in a u64");
        };
    };
}

parameter_set!(
    "sha2-128s",
    Sha2_128s,
    "SLH-DSA-SHA2-128s",
    Sha2Cat1<16>,
    category = 1,
    n = 16,
    h = 63,
    d = 7,
    hp = 9,
    a = 12,
    k = 14,
    m = 30,
    sig = 7856
);
parameter_set!(
    "shake-128s",
    Shake128s,
    "SLH-DSA-SHAKE-128s",
    ShakeSuite<16>,
    category = 1,
    n = 16,
    h = 63,
    d = 7,
    hp = 9,
    a = 12,
    k = 14,
    m = 30,
    sig = 7856
);
parameter_set!(
    "sha2-128f",
    Sha2_128f,
    "SLH-DSA-SHA2-128f",
    Sha2Cat1<16>,
    category = 1,
    n = 16,
    h = 66,
    d = 22,
    hp = 3,
    a = 6,
    k = 33,
    m = 34,
    sig = 17088
);
parameter_set!(
    "shake-128f",
    Shake128f,
    "SLH-DSA-SHAKE-128f",
    ShakeSuite<16>,
    category = 1,
    n = 16,
    h = 66,
    d = 22,
    hp = 3,
    a = 6,
    k = 33,
    m = 34,
    sig = 17088
);
parameter_set!(
    "sha2-192s",
    Sha2_192s,
    "SLH-DSA-SHA2-192s",
    Sha2Cat35<24>,
    category = 3,
    n = 24,
    h = 63,
    d = 7,
    hp = 9,
    a = 14,
    k = 17,
    m = 39,
    sig = 16224
);
parameter_set!(
    "shake-192s",
    Shake192s,
    "SLH-DSA-SHAKE-192s",
    ShakeSuite<24>,
    category = 3,
    n = 24,
    h = 63,
    d = 7,
    hp = 9,
    a = 14,
    k = 17,
    m = 39,
    sig = 16224
);
parameter_set!(
    "sha2-192f",
    Sha2_192f,
    "SLH-DSA-SHA2-192f",
    Sha2Cat35<24>,
    category = 3,
    n = 24,
    h = 66,
    d = 22,
    hp = 3,
    a = 8,
    k = 33,
    m = 42,
    sig = 35664
);
parameter_set!(
    "shake-192f",
    Shake192f,
    "SLH-DSA-SHAKE-192f",
    ShakeSuite<24>,
    category = 3,
    n = 24,
    h = 66,
    d = 22,
    hp = 3,
    a = 8,
    k = 33,
    m = 42,
    sig = 35664
);
parameter_set!(
    "sha2-256s",
    Sha2_256s,
    "SLH-DSA-SHA2-256s",
    Sha2Cat35<32>,
    category = 5,
    n = 32,
    h = 64,
    d = 8,
    hp = 8,
    a = 14,
    k = 22,
    m = 47,
    sig = 29792
);
parameter_set!(
    "shake-256s",
    Shake256s,
    "SLH-DSA-SHAKE-256s",
    ShakeSuite<32>,
    category = 5,
    n = 32,
    h = 64,
    d = 8,
    hp = 8,
    a = 14,
    k = 22,
    m = 47,
    sig = 29792
);
parameter_set!(
    "sha2-256f",
    Sha2_256f,
    "SLH-DSA-SHA2-256f",
    Sha2Cat35<32>,
    category = 5,
    n = 32,
    h = 68,
    d = 17,
    hp = 4,
    a = 9,
    k = 35,
    m = 49,
    sig = 49856
);
parameter_set!(
    "shake-256f",
    Shake256f,
    "SLH-DSA-SHAKE-256f",
    ShakeSuite<32>,
    category = 5,
    n = 32,
    h = 68,
    d = 17,
    hp = 4,
    a = 9,
    k = 35,
    m = 49,
    sig = 49856
);

#[cfg(test)]
mod tests {
    use super::gen_len2;

    #[test]
    fn len2_is_three_for_lg_w_4() {
        assert_eq!(gen_len2(16, 4), 3);
        assert_eq!(gen_len2(24, 4), 3);
        assert_eq!(gen_len2(32, 4), 3);
    }

    /// Algorithm 1 is defined for any lg_w. Other widths reach the loop's boundary cases, which
    /// lg_w = 4 never does: max_checksum = 8 equals w^3 for w = 2.
    #[test]
    fn len2_for_other_widths() {
        assert_eq!(gen_len2(1, 1), 4);
        assert_eq!(gen_len2(32, 2), 5);
        assert_eq!(gen_len2(32, 8), 2);
    }
}
