use core::fmt;

/// Errors from key handling and signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// The context string is longer than 255 bytes (FIPS 205 Algorithms 22-25).
    ContextTooLong,
    /// A key encoding has the wrong length for the parameter set.
    InvalidKeyLength,
    /// A signature encoding has the wrong length for the parameter set.
    InvalidSignatureLength,
    /// A pre-hash digest has the wrong length for its hash function.
    InvalidDigestLength,
    /// SHA-256 or SHAKE128 pre-hashing with a category 3 or 5 parameter set (FIPS 205 §10.2.2).
    PreHashTooWeak,
    /// A pure signing call on a pre-hash key, a pre-hash call on a pure key, or the wrong hash.
    UsageMismatch,
    /// An imported secret key's PK.root does not match its SK.seed and PK.seed.
    InconsistentKey,
    /// The random number generator failed (FIPS 205 Algorithm 21 and Algorithm 22, line 6).
    Entropy,
    /// The fault check rejected the signature. No signature is returned; investigate the host.
    SelfCheckFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::ContextTooLong => "context string longer than 255 bytes",
            Error::InvalidKeyLength => "key encoding has the wrong length",
            Error::InvalidSignatureLength => "signature encoding has the wrong length",
            Error::InvalidDigestLength => "pre-hash digest has the wrong length",
            Error::PreHashTooWeak => "pre-hash function too weak for this parameter set",
            Error::UsageMismatch => "operation does not match the key's configured usage",
            Error::InconsistentKey => "secret key is internally inconsistent",
            Error::Entropy => "random number generation failed",
            Error::SelfCheckFailed => "signature failed the fault check",
        })
    }
}

impl core::error::Error for Error {}

/// Signature verification failed. Deliberately carries no reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct VerificationError;

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("signature verification failed")
    }
}

impl core::error::Error for VerificationError {}
