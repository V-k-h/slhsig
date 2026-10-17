//! SLH-DSA, the stateless hash-based signature scheme of [FIPS 205], written from the standard.
//!
//! **Status: experimental (0.1).** The implementation passes NIST's ACVP test vectors for all 12
//! parameter sets but has not been independently reviewed. Do not rely on it for production
//! security until it has been.
//!
//! # Usage
//!
//! ```
//! # #[cfg(all(feature = "os-rng", feature = "shake-128f"))] {
//! use slhsig::{Context, Shake128f, SigningKey};
//!
//! let sk = SigningKey::<Shake128f>::generate()?;           // hedged signing by default
//! let vk = sk.verifying_key();
//! let ctx = Context::new(b"example-protocol v1")?;
//! let sig = sk.sign(b"message", ctx)?;
//! assert!(vk.verify(b"message", ctx, &sig).is_ok());
//! # }
//! # Ok::<(), slhsig::Error>(())
//! ```
//!
//! # Design
//!
//! - Each parameter set is a type (`Shake128f`, `Sha2_256s`, ...), selected by a Cargo feature.
//! - The signing variant is part of the key's type: [`SigningKey<P, Hedged>`] (the default) or
//!   [`SigningKey<P, Deterministic>`]. FIPS 205 asks that a key serve one variant only.
//! - Contexts ([`Context`]) and pre-hash digests ([`PreHashed`]) are validated on construction.
//! - Every signature passes a [`FaultCheck`] before it is returned. The default signs twice and
//!   compares, so a fault in one of the two runs is caught before the signature is released.
//! - Secret seeds are zeroized on drop; there is no `unsafe` code.
//!
//! [FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// With no parameter-set feature enabled the algorithms have no callers; that build is only
// useful for checking feature combinations, so dead code is expected there.
#![cfg_attr(
    not(any(
        feature = "sha2-128s",
        feature = "sha2-128f",
        feature = "sha2-192s",
        feature = "sha2-192f",
        feature = "sha2-256s",
        feature = "sha2-256f",
        feature = "shake-128s",
        feature = "shake-128f",
        feature = "shake-192s",
        feature = "shake-192f",
        feature = "shake-256s",
        feature = "shake-256f"
    )),
    allow(dead_code)
)]

extern crate alloc;

mod adrs;
mod api;
mod encoding;
mod fors;
mod hash;
mod hypertree;
mod params;
mod slh;
mod wots;
mod xmss;

#[cfg(feature = "hazmat")]
pub mod hazmat;

pub use api::{
    Context, Deterministic, Error, FaultCheck, Hedged, KeyUsage, PreHash, PreHashDigest, PreHashed,
    Signature, SigningKey, Variant, VerificationError, VerifyingKey,
};
pub use params::ParameterSet;

#[cfg(feature = "sha2-128f")]
pub use params::Sha2_128f;
#[cfg(feature = "sha2-128s")]
pub use params::Sha2_128s;
#[cfg(feature = "sha2-192f")]
pub use params::Sha2_192f;
#[cfg(feature = "sha2-192s")]
pub use params::Sha2_192s;
#[cfg(feature = "sha2-256f")]
pub use params::Sha2_256f;
#[cfg(feature = "sha2-256s")]
pub use params::Sha2_256s;
#[cfg(feature = "shake-128f")]
pub use params::Shake128f;
#[cfg(feature = "shake-128s")]
pub use params::Shake128s;
#[cfg(feature = "shake-192f")]
pub use params::Shake192f;
#[cfg(feature = "shake-192s")]
pub use params::Shake192s;
#[cfg(feature = "shake-256f")]
pub use params::Shake256f;
#[cfg(feature = "shake-256s")]
pub use params::Shake256s;

/// Re-exported so callers can name the RNG traits this crate accepts.
pub use rand_core;
