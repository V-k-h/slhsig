//! Integer and base-2^b conversions (FIPS 205 Section 4.4, Algorithms 2-4).

/// Algorithm 2: `toInt(X, n)`. Big-endian; `x` is at most 8 bytes long.
pub(crate) fn to_int(x: &[u8]) -> u64 {
    debug_assert!(x.len() <= 8);
    // 1: total <- 0
    let mut total: u64 = 0;
    // 2: for i from 0 to n - 1 do
    for &byte in x {
        // 3: total <- 256 * total + X[i]
        total = (total << 8) | u64::from(byte);
    }
    // 5: return total
    total
}

/// Algorithm 3: `toByte(x, n)`. Writes the big-endian encoding of `x` into all of `out`.
pub(crate) fn to_byte(x: u64, out: &mut [u8]) {
    // 1: total <- x
    let mut total = x;
    let n = out.len();
    // 2: for i from 0 to n - 1 do
    for i in 0..n {
        // 3: S[n - 1 - i] <- total mod 256
        out[n - 1 - i] = total as u8;
        // 4: total <- total >> 8
        total = total.checked_shr(8).unwrap_or(0);
    }
}

/// Algorithm 4: `base_2b(X, b, out_len)`. Fills all of `out` with b-bit digits of `x`.
///
/// `x` must hold at least ceil(out.len() * b / 8) bytes and `b` must be at most 24.
pub(crate) fn base_2b(x: &[u8], b: u32, out: &mut [u32]) {
    debug_assert!((1..=24).contains(&b));
    debug_assert!(x.len() >= (out.len() * b as usize).div_ceil(8));
    // 1-3: in <- 0; bits <- 0; total <- 0
    let mut input = 0usize;
    let mut bits: u32 = 0;
    let mut total: u32 = 0;
    let mask = (1u32 << b) - 1;
    // 4: for out from 0 to out_len - 1 do
    for digit in out.iter_mut() {
        // 5: while bits < b do
        while bits < b {
            // 6: total <- (total << 8) + X[in]. Bits shifted past bit 31 are never read again.
            total = (total << 8) | u32::from(x[input]);
            // 7-8: in <- in + 1; bits <- bits + 8
            input += 1;
            bits += 8;
        }
        // 10: bits <- bits - b
        bits -= b;
        // 11: baseb[out] <- (total >> bits) mod 2^b
        *digit = (total >> bits) & mask;
    }
}

/// A mask of the `bits` least significant bits. Handles `bits == 64`, which
/// SLH-DSA-*-256f needs for idx_tree (h - h/d = 64), where `1 << 64` would overflow.
pub(crate) const fn low_bits_mask(bits: usize) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_int_big_endian() {
        assert_eq!(to_int(&[]), 0);
        assert_eq!(to_int(&[0x01, 0x02]), 0x0102);
        assert_eq!(to_int(&[0xff; 8]), u64::MAX);
        assert_eq!(to_int(&[0x80, 0, 0, 0, 0, 0, 0, 1]), 0x8000_0000_0000_0001);
    }

    #[test]
    fn to_byte_big_endian() {
        let mut out = [0u8; 4];
        to_byte(0x0102_0304, &mut out);
        assert_eq!(out, [1, 2, 3, 4]);
        let mut wide = [0xaau8; 12];
        to_byte(u64::MAX, &mut wide);
        assert_eq!(wide, [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let mut short = [0u8; 2];
        to_byte(0x1_2345, &mut short);
        assert_eq!(short, [0x23, 0x45]);
    }

    #[test]
    fn to_int_inverts_to_byte() {
        for x in [0u64, 1, 0xff, 0x1234_5678_9abc_def0, u64::MAX] {
            let mut buf = [0u8; 8];
            to_byte(x, &mut buf);
            assert_eq!(to_int(&buf), x);
        }
    }

    #[test]
    fn base_2b_nibbles() {
        let mut out = [0u32; 4];
        base_2b(&[0xab, 0xcd], 4, &mut out);
        assert_eq!(out, [0xa, 0xb, 0xc, 0xd]);
    }

    #[test]
    fn base_2b_unaligned_widths() {
        // 0b1010_1100 0b0011_0101 0b1111_0000 read as 6-bit digits.
        let mut out = [0u32; 4];
        base_2b(&[0b1010_1100, 0b0011_0101, 0b1111_0000], 6, &mut out);
        assert_eq!(out, [0b101011, 0b000011, 0b010111, 0b110000]);
        // 14-bit digits (a = 14) spanning three bytes.
        let mut wide = [0u32; 2];
        base_2b(&[0xff, 0xfc, 0x00, 0x03], 14, &mut wide);
        assert_eq!(wide, [0x3fff, 0x0000]);
        // Bits 14..28 of 00000000 00000000 00001111 11111111 are 00 00001111 1111.
        let mut wide2 = [0u32; 2];
        base_2b(&[0x00, 0x00, 0x0f, 0xff], 14, &mut wide2);
        assert_eq!(wide2, [0, 0xff]);
    }

    #[test]
    fn base_2b_reads_only_needed_bytes() {
        // k * a = 33 * 6 = 198 bits needs 25 bytes; a 25-byte input must suffice.
        let x = [0x55u8; 25];
        let mut out = [0u32; 33];
        base_2b(&x, 6, &mut out);
        assert!(out.iter().all(|&d| d < 64));
    }

    #[test]
    fn mask_handles_64_bits() {
        assert_eq!(low_bits_mask(0), 0);
        assert_eq!(low_bits_mask(3), 0b111);
        assert_eq!(low_bits_mask(63), u64::MAX >> 1);
        assert_eq!(low_bits_mask(64), u64::MAX);
    }
}
