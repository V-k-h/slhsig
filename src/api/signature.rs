use super::error::Error;
use crate::params::ParameterSet;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

/// An SLH-DSA signature for parameter set `P`: exactly `P::SIG_BYTES` bytes, heap-allocated.
pub struct Signature<P: ParameterSet> {
    bytes: Box<[u8]>,
    _p: PhantomData<P>,
}

impl<P: ParameterSet> Signature<P> {
    /// Parses a signature, rejecting any length other than `P::SIG_BYTES`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == P::SIG_BYTES {
            Ok(Self { bytes: bytes.into(), _p: PhantomData })
        } else {
            Err(Error::InvalidSignatureLength)
        }
    }

    /// Takes ownership of a buffer of exactly `P::SIG_BYTES` bytes.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() == P::SIG_BYTES {
            Ok(Self { bytes: bytes.into_boxed_slice(), _p: PhantomData })
        } else {
            Err(Error::InvalidSignatureLength)
        }
    }

    pub(crate) fn from_trusted(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::SIG_BYTES);
        Self { bytes: bytes.into_boxed_slice(), _p: PhantomData }
    }

    /// The encoded signature, `R || SIG_FORS || SIG_HT`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the signature, returning its bytes.
    pub fn into_bytes(self) -> Box<[u8]> {
        self.bytes
    }
}

impl<P: ParameterSet> AsRef<[u8]> for Signature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: ParameterSet> TryFrom<&[u8]> for Signature<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes)
    }
}

impl<P: ParameterSet> Clone for Signature<P> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes.clone(), _p: PhantomData }
    }
}

impl<P: ParameterSet> PartialEq for Signature<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: ParameterSet> Eq for Signature<P> {}

impl<P: ParameterSet> Hash for Signature<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<P: ParameterSet> fmt::Debug for Signature<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature<{}>(R = ", P::NAME)?;
        for b in &self.bytes[..P::N] {
            write!(f, "{b:02x}")?;
        }
        write!(f, ", {} bytes)", self.bytes.len())
    }
}
