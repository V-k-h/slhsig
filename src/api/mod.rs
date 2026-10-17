//! The public API: typed keys, signatures, contexts and pre-hash digests.

mod context;
mod error;
mod integrations;
mod keys;
mod sign;
mod signature;
mod verify;

pub use context::{Context, FaultCheck, KeyUsage, PreHash, PreHashDigest, PreHashed};
pub use error::{Error, VerificationError};
pub use keys::{Deterministic, Hedged, SigningKey, Variant, VerifyingKey};
pub use signature::Signature;
