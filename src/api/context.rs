use super::error::Error;
use sha2::Digest;
use shake::digest::{ExtendableOutput, Update};

/// A FIPS 205 context string: at most 255 bytes, bound into every signature.
///
/// The length limit is checked when the value is built, so signing and verification never see
/// an over-long context. Use [`Context::EMPTY`] when the protocol defines no context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Context<'a>(&'a [u8]);

impl<'a> Context<'a> {
    /// The empty context string, FIPS 205's default.
    pub const EMPTY: Context<'static> = Context(&[]);

    /// Wraps `ctx`, rejecting strings longer than 255 bytes.
    pub const fn new(ctx: &'a [u8]) -> Result<Self, Error> {
        if ctx.len() > 255 { Err(Error::ContextTooLong) } else { Ok(Self(ctx)) }
    }

    /// The context bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// `toByte(|ctx|, 1)`.
    pub(crate) const fn len_byte(&self) -> u8 {
        self.0.len() as u8
    }
}

/// Hash functions approved for HashSLH-DSA in this crate (FIPS 205 Algorithm 23).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PreHash {
    /// SHA-256 (32-byte digest). Category 1 parameter sets only.
    Sha256,
    /// SHA-512 (64-byte digest).
    Sha512,
    /// SHAKE128 with 256-bit output. Category 1 parameter sets only.
    Shake128,
    /// SHAKE256 with 512-bit output.
    Shake256,
}

impl PreHash {
    /// Digest length in bytes.
    pub const fn digest_len(self) -> usize {
        match self {
            PreHash::Sha256 | PreHash::Shake128 => 32,
            PreHash::Sha512 | PreHash::Shake256 => 64,
        }
    }

    /// The DER encoding (tag, length, value) of the hash function's OID, from Algorithm 23.
    pub const fn oid_der(self) -> &'static [u8; 11] {
        match self {
            // 2.16.840.1.101.3.4.2.1
            PreHash::Sha256 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            // 2.16.840.1.101.3.4.2.3
            PreHash::Sha512 => &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            // 2.16.840.1.101.3.4.2.11
            PreHash::Shake128 => {
                &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b]
            }
            // 2.16.840.1.101.3.4.2.12
            PreHash::Shake256 => {
                &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c]
            }
        }
    }

    /// Whether FIPS 205 §10.2.2 considers this hash appropriate for a parameter set of the
    /// given security category: SHA-256 and SHAKE128 only for category 1.
    pub const fn suits_category(self, category: u8) -> bool {
        match self {
            PreHash::Sha256 | PreHash::Shake128 => category == 1,
            PreHash::Sha512 | PreHash::Shake256 => true,
        }
    }

    /// Computes `PH(M)` for this hash function.
    pub fn digest(self, msg: &[u8]) -> PreHashDigest {
        let mut bytes = [0u8; 64];
        match self {
            PreHash::Sha256 => bytes[..32].copy_from_slice(&sha2::Sha256::digest(msg)),
            PreHash::Sha512 => bytes.copy_from_slice(&sha2::Sha512::digest(msg)),
            PreHash::Shake128 => {
                let mut h = shake::Shake128::default();
                h.update(msg);
                h.finalize_xof_into(&mut bytes[..32]);
            }
            PreHash::Shake256 => {
                let mut h = shake::Shake256::default();
                h.update(msg);
                h.finalize_xof_into(&mut bytes);
            }
        }
        PreHashDigest { alg: self, bytes }
    }
}

/// An owned pre-hash digest, as returned by [`PreHash::digest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PreHashDigest {
    alg: PreHash,
    bytes: [u8; 64],
}

impl PreHashDigest {
    /// Borrows the digest for [`sign_prehashed`](crate::SigningKey) or `verify_prehashed`.
    pub fn as_prehashed(&self) -> PreHashed<'_> {
        PreHashed { alg: self.alg, digest: &self.bytes[..self.alg.digest_len()] }
    }
}

/// A digest tagged with the hash function that produced it. Its length is checked on creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PreHashed<'a> {
    alg: PreHash,
    digest: &'a [u8],
}

impl<'a> PreHashed<'a> {
    /// Tags `digest` as the output of `alg`, rejecting a digest of the wrong length.
    pub const fn new(alg: PreHash, digest: &'a [u8]) -> Result<Self, Error> {
        if digest.len() == alg.digest_len() {
            Ok(Self { alg, digest })
        } else {
            Err(Error::InvalidDigestLength)
        }
    }

    /// The hash function.
    pub const fn alg(&self) -> PreHash {
        self.alg
    }

    /// The digest bytes.
    pub const fn digest(&self) -> &'a [u8] {
        self.digest
    }
}

/// What a signing key may sign. FIPS 205 §10.2 recommends one mode per key pair.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    /// Pure SLH-DSA (Algorithm 22): the message itself is signed. The default.
    #[default]
    Pure,
    /// HashSLH-DSA (Algorithm 23) with exactly this hash function.
    PreHash(PreHash),
}

/// The fault check run on every signature before it is returned.
///
/// A single faulted signature can enable universal forgery ("Grafting Trees", ePrint 2018/102),
/// and such signatures still verify. `Redundant`, the default, signs twice and compares, which
/// catches those faults at about twice the signing cost. `Verify` only catches faults that break
/// validity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FaultCheck {
    /// No check.
    None,
    /// Verify the signature before returning it.
    Verify,
    /// Sign twice from the same inputs, compare the byte strings, then verify. The default.
    #[default]
    Redundant,
}
