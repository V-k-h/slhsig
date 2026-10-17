//! Shared helpers for the differential tests: a reproducible case generator and fixed-output
//! RNGs for both `rand_core` generations the oracles use.

use core::convert::Infallible;

/// SplitMix64: a small, reproducible generator for test inputs (not for keys).
pub struct Cases(u64);

impl Cases {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }

    /// A length in `0..=max`, biased toward the edges (0, 1, max - 1, max).
    pub fn len(&mut self, max: usize) -> usize {
        match self.next_u64() % 8 {
            0 => 0,
            1 => 1.min(max),
            2 => max.saturating_sub(1),
            3 => max,
            _ => (self.next_u64() % (max as u64 + 1)) as usize,
        }
    }
}

/// Number of cases per parameter set: `SLHSIG_DIFF_CASES`, or `default`.
pub fn case_count(default: usize) -> usize {
    std::env::var("SLHSIG_DIFF_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Replays fixed bytes through `rand_core` 0.10 (slhsig, RustCrypto `slh-dsa`).
pub struct Fixed<'a>(pub &'a [u8]);

impl rand_core::TryRng for Fixed<'_> {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unimplemented!("only fill_bytes is used")
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unimplemented!("only fill_bytes is used")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let (head, tail) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = tail;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Fixed<'_> {}

/// Replays fixed bytes through `rand_core` 0.6 (integritychain `fips205`).
pub struct Fixed06<'a>(pub &'a [u8]);

impl rand_core_06::RngCore for Fixed06<'_> {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("only fill_bytes is used")
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!("only fill_bytes is used")
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let (head, tail) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = tail;
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for Fixed06<'_> {}
