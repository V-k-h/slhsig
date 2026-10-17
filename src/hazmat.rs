//! FIPS 205 internal functions (Algorithms 18-20), for test vectors and differential testing.
//!
//! **Do not enable the `hazmat` feature in production.** These functions take seeds and
//! per-signature randomness from the caller, skip context handling and domain separation, and
//! run no fault check. Misuse breaks SLH-DSA's security.

use crate::api::{Error, SigningKey, Variant};
use crate::hash::{ByteArray, MsgParts};
use crate::params::{NodeOf, ParameterSet};
use crate::slh;
use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroizing;

fn node<P: ParameterSet>(bytes: &[u8]) -> Result<NodeOf<P>, Error> {
    if bytes.len() == P::N {
        Ok(NodeOf::<P>::copy_from(bytes))
    } else {
        Err(Error::InvalidKeyLength)
    }
}

impl<P: ParameterSet, V: Variant> SigningKey<P, V> {
    /// Algorithm 18 with caller-supplied SK.seed, SK.prf and PK.seed (n bytes each).
    pub fn from_seeds(sk_seed: &[u8], sk_prf: &[u8], pk_seed: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_seed_nodes(node::<P>(sk_seed)?, node::<P>(sk_prf)?, node::<P>(pk_seed)?))
    }
}

/// Algorithm 18: `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`, returning `(SK, PK)` encodings.
pub fn keygen_internal<P: ParameterSet>(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(Zeroizing<P::SkBytes>, P::PkBytes), Error> {
    let key = SigningKey::<P>::from_seeds(sk_seed, sk_prf, pk_seed)?;
    Ok((key.to_bytes(), key.verifying_key().to_bytes()))
}

/// Algorithm 19: `slh_sign_internal(M, SK, addrnd)` on a raw M. `addrnd = None` is the
/// deterministic variant. The secret key is decoded without the PK.root check.
pub fn sign_internal<P: ParameterSet>(
    sk: &[u8],
    msg: &[u8],
    addrnd: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if sk.len() != P::SK_BYTES {
        return Err(Error::InvalidKeyLength);
    }
    let sk = Zeroizing::new(P::SkBytes::copy_from(sk));
    let key = SigningKey::<P>::from_bytes_unchecked(&sk);
    let addrnd = addrnd.map(node::<P>).transpose()?.map(Zeroizing::new);
    let mut sig = vec![0u8; P::SIG_BYTES];
    slh::sign_internal::<P>(MsgParts(&[msg]), &key.sign_inputs(), addrnd.as_deref(), &mut sig);
    Ok(sig)
}

/// Algorithm 20: `slh_verify_internal(M, SIG, PK)` on a raw M. Wrong lengths return `false`.
pub fn verify_internal<P: ParameterSet>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match crate::api::VerifyingKey::<P>::from_slice(pk) {
        Ok(vk) => vk.verify_parts(MsgParts(&[msg]), sig),
        Err(_) => false,
    }
}
