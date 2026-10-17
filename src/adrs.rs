//! Hash function addresses (FIPS 205 Section 4.2, Figure 2 and Table 1).
//!
//! Layout of the 32-byte ADRS, all words big-endian:
//!
//! | bytes  | field                                        |
//! |--------|----------------------------------------------|
//! | 0..4   | layer address                                |
//! | 4..16  | tree address (bytes 4..8 are always zero)    |
//! | 16..20 | type                                         |
//! | 20..24 | key pair address                             |
//! | 24..28 | chain address / tree height                  |
//! | 28..32 | hash address / tree index                    |

/// Address types (FIPS 205 Section 4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum AdrsType {
    WotsHash = 0,
    WotsPk = 1,
    Tree = 2,
    ForsTree = 3,
    ForsRoots = 4,
    WotsPrf = 5,
    ForsPrf = 6,
}

/// The full 32-byte address. SHA2 suites derive the 22-byte ADRSc from it on demand.
///
/// Nominally `pub` (but unnameable) because it appears in the sealed `HashSuite` trait.
#[allow(unreachable_pub)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adrs([u8; 32]);

impl Adrs {
    /// `ADRS <- toByte(0, 32)`.
    pub(crate) const fn new() -> Self {
        Self([0u8; 32])
    }

    fn put_u32(&mut self, at: usize, value: u32) {
        self.0[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn get_u32(&self, at: usize) -> u32 {
        u32::from_be_bytes([self.0[at], self.0[at + 1], self.0[at + 2], self.0[at + 3]])
    }

    /// `ADRS.setLayerAddress(l)`: `toByte(l, 4) || ADRS[4:32]`.
    pub(crate) fn set_layer(&mut self, layer: u32) {
        self.put_u32(0, layer);
    }

    /// `ADRS.setTreeAddress(t)`: `ADRS[0:4] || toByte(t, 12) || ADRS[16:32]`.
    ///
    /// Tree indices never exceed 64 bits for the approved parameter sets, so the
    /// top four bytes of the 12-byte field are always zero.
    pub(crate) fn set_tree(&mut self, tree: u64) {
        self.0[4..8].fill(0);
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// `ADRS.setTypeAndClear(Y)`: `ADRS[0:16] || toByte(Y, 4) || toByte(0, 12)`.
    pub(crate) fn set_type_and_clear(&mut self, ty: AdrsType) {
        self.put_u32(16, ty as u32);
        self.0[20..32].fill(0);
    }

    /// `ADRS.setKeyPairAddress(i)`: `ADRS[0:20] || toByte(i, 4) || ADRS[24:32]`.
    pub(crate) fn set_key_pair(&mut self, i: u32) {
        self.put_u32(20, i);
    }

    /// `ADRS.setChainAddress(i)`: `ADRS[0:24] || toByte(i, 4) || ADRS[28:32]`.
    pub(crate) fn set_chain(&mut self, i: u32) {
        self.put_u32(24, i);
    }

    /// `ADRS.setTreeHeight(i)`: same bytes as the chain address.
    pub(crate) fn set_tree_height(&mut self, i: u32) {
        self.put_u32(24, i);
    }

    /// `ADRS.setHashAddress(i)`: `ADRS[0:28] || toByte(i, 4)`.
    pub(crate) fn set_hash(&mut self, i: u32) {
        self.put_u32(28, i);
    }

    /// `ADRS.setTreeIndex(i)`: same bytes as the hash address.
    pub(crate) fn set_tree_index(&mut self, i: u32) {
        self.put_u32(28, i);
    }

    /// `ADRS.getKeyPairAddress()`: `toInt(ADRS[20:24], 4)`.
    pub(crate) fn key_pair(&self) -> u32 {
        self.get_u32(20)
    }

    /// `ADRS.getTreeIndex()`: `toInt(ADRS[28:32], 4)`.
    pub(crate) fn tree_index(&self) -> u32 {
        self.get_u32(28)
    }

    /// The full 32-byte address, used by the SHAKE suite.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// FIPS 205 Section 11.2: `ADRSc = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]`.
    pub(crate) fn compressed(&self) -> [u8; 22] {
        let mut c = [0u8; 22];
        c[0] = self.0[3];
        c[1..9].copy_from_slice(&self.0[8..16]);
        c[9] = self.0[19];
        c[10..22].copy_from_slice(&self.0[20..32]);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setters_follow_table_1() {
        let mut a = Adrs::new();
        a.set_layer(0x0102_0304);
        a.set_tree(0x1112_1314_1516_1718);
        a.set_type_and_clear(AdrsType::ForsTree);
        a.set_key_pair(0x2122_2324);
        a.set_tree_height(0x3132_3334);
        a.set_tree_index(0x4142_4344);
        let expected: [u8; 32] = [
            1, 2, 3, 4, // layer
            0, 0, 0, 0, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // tree
            0, 0, 0, 3, // type
            0x21, 0x22, 0x23, 0x24, // key pair
            0x31, 0x32, 0x33, 0x34, // tree height
            0x41, 0x42, 0x43, 0x44, // tree index
        ];
        assert_eq!(a.as_bytes(), &expected);
        assert_eq!(a.key_pair(), 0x2122_2324);
        assert_eq!(a.tree_index(), 0x4142_4344);
    }

    #[test]
    fn set_type_clears_final_twelve_bytes_only() {
        let mut a = Adrs::new();
        a.set_layer(7);
        a.set_tree(9);
        a.set_key_pair(1);
        a.set_chain(2);
        a.set_hash(3);
        a.set_type_and_clear(AdrsType::WotsPk);
        let b = a.as_bytes();
        assert_eq!(&b[0..4], &[0, 0, 0, 7]);
        assert_eq!(&b[8..16], &9u64.to_be_bytes());
        assert_eq!(&b[16..20], &[0, 0, 0, 1]);
        assert!(b[20..32].iter().all(|&x| x == 0));
    }

    #[test]
    fn compressed_layout() {
        let mut a = Adrs::new();
        a.set_layer(5);
        a.set_tree(0x0a0b_0c0d_0e0f_1011);
        a.set_type_and_clear(AdrsType::Tree);
        a.set_tree_height(6);
        a.set_tree_index(0x0102_0304);
        let c = a.compressed();
        assert_eq!(c[0], 5);
        assert_eq!(&c[1..9], &0x0a0b_0c0d_0e0f_1011u64.to_be_bytes());
        assert_eq!(c[9], 2);
        assert_eq!(&c[10..14], &[0, 0, 0, 0]);
        assert_eq!(&c[14..18], &[0, 0, 0, 6]);
        assert_eq!(&c[18..22], &[1, 2, 3, 4]);
    }
}
