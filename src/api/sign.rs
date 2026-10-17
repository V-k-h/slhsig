//! Signature generation: Algorithms 22 (pure) and 23 (pre-hash), plus the fault check.

use super::context::{Context, FaultCheck, KeyUsage, PreHash, PreHashed};
use super::error::Error;
use super::keys::{Deterministic, Hedged, SigningKey, Variant};
use super::signature::Signature;
use crate::hash::{ByteArray, MsgParts};
use crate::params::{NodeOf, ParameterSet};
use crate::slh;
use alloc::vec;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, Zeroizing};

/// Domain separator for pure signing (Algorithm 22, line 8).
pub(crate) const PURE: u8 = 0;
/// Domain separator for pre-hash signing (Algorithm 23, line 24).
pub(crate) const PREHASH: u8 = 1;

/// Draws addrnd. Algorithm 22, lines 4-7: an RBG failure is an error, never a weaker signature.
fn draw_addrnd<P: ParameterSet, R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<Zeroizing<NodeOf<P>>, Error> {
    let mut addrnd = Zeroizing::new(NodeOf::<P>::zeroed());
    rng.try_fill_bytes(addrnd.as_mut()).map_err(|_| Error::Entropy)?;
    Ok(addrnd)
}

impl<P: ParameterSet, V: Variant> SigningKey<P, V> {
    fn require_pure(&self) -> Result<(), Error> {
        match self.usage() {
            KeyUsage::Pure => Ok(()),
            KeyUsage::PreHash(_) => Err(Error::UsageMismatch),
        }
    }

    fn require_prehash(&self, alg: PreHash) -> Result<(), Error> {
        if !alg.suits_category(P::CATEGORY) {
            return Err(Error::PreHashTooWeak);
        }
        match self.usage() {
            KeyUsage::PreHash(configured) if configured == alg => Ok(()),
            _ => Err(Error::UsageMismatch),
        }
    }

    /// Algorithm 22: pure signing. `addrnd = None` selects the deterministic variant.
    fn sign_pure(
        &self,
        addrnd: Option<&NodeOf<P>>,
        msg: &[u8],
        ctx: Context<'_>,
    ) -> Result<Signature<P>, Error> {
        self.require_pure()?;
        // 8: M' <- toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
        let head = [PURE, ctx.len_byte()];
        let parts: [&[u8]; 3] = [&head, ctx.as_bytes(), msg];
        // 9: SIG <- slh_sign_internal(M', SK, addrnd)
        self.sign_checked(MsgParts(&parts), addrnd)
    }

    /// Algorithm 23: pre-hash signing. `addrnd = None` selects the deterministic variant.
    fn sign_prehash(
        &self,
        addrnd: Option<&NodeOf<P>>,
        digest: PreHashed<'_>,
        ctx: Context<'_>,
    ) -> Result<Signature<P>, Error> {
        self.require_prehash(digest.alg())?;
        // 24: M' <- toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH_M
        let head = [PREHASH, ctx.len_byte()];
        let parts: [&[u8]; 4] = [&head, ctx.as_bytes(), digest.alg().oid_der(), digest.digest()];
        // 25: SIG <- slh_sign_internal(M', SK, addrnd)
        self.sign_checked(MsgParts(&parts), addrnd)
    }

    /// Algorithm 19 followed by the configured fault check. A rejected signature is zeroized
    /// and never returned: a faulted SLH-DSA signature can leak enough to forge.
    pub(crate) fn sign_checked(
        &self,
        msg: MsgParts<'_>,
        addrnd: Option<&NodeOf<P>>,
    ) -> Result<Signature<P>, Error> {
        let inputs = self.sign_inputs();
        let mut sig = vec![0u8; P::SIG_BYTES];
        slh::sign_internal::<P>(msg, &inputs, addrnd, &mut sig);

        let ok = match self.fault_check() {
            FaultCheck::None => true,
            FaultCheck::Verify => self.as_verifying_key().verify_parts(msg, &sig),
            FaultCheck::Redundant => {
                let mut again = vec![0u8; P::SIG_BYTES];
                slh::sign_internal::<P>(msg, &inputs, addrnd, &mut again);
                let same = sig == again;
                again.zeroize();
                same && self.as_verifying_key().verify_parts(msg, &sig)
            }
        };
        if ok {
            Ok(Signature::from_trusted(sig))
        } else {
            sig.zeroize();
            Err(Error::SelfCheckFailed)
        }
    }
}

impl<P: ParameterSet> SigningKey<P, Hedged> {
    /// Hedged pure signing (Algorithm 22) with randomness from `rng`.
    pub fn try_sign<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
        ctx: Context<'_>,
    ) -> Result<Signature<P>, Error> {
        let addrnd = draw_addrnd::<P, R>(rng)?;
        self.sign_pure(Some(&*addrnd), msg, ctx)
    }

    /// Hedged pre-hash signing (Algorithm 23) with randomness from `rng`.
    pub fn try_sign_prehashed<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        digest: PreHashed<'_>,
        ctx: Context<'_>,
    ) -> Result<Signature<P>, Error> {
        let addrnd = draw_addrnd::<P, R>(rng)?;
        self.sign_prehash(Some(&*addrnd), digest, ctx)
    }

    /// Hedged pure signing with randomness from the operating system (`getrandom::SysRng`).
    #[cfg(feature = "os-rng")]
    pub fn sign(&self, msg: &[u8], ctx: Context<'_>) -> Result<Signature<P>, Error> {
        self.try_sign(&mut getrandom::SysRng, msg, ctx)
    }

    /// Hedged pre-hash signing with randomness from the operating system.
    #[cfg(feature = "os-rng")]
    pub fn sign_prehashed(
        &self,
        digest: PreHashed<'_>,
        ctx: Context<'_>,
    ) -> Result<Signature<P>, Error> {
        self.try_sign_prehashed(&mut getrandom::SysRng, digest, ctx)
    }
}

impl<P: ParameterSet> SigningKey<P, Deterministic> {
    /// Deterministic pure signing (Algorithm 22, deterministic variant).
    pub fn sign(&self, msg: &[u8], ctx: Context<'_>) -> Result<Signature<P>, Error> {
        self.sign_pure(None, msg, ctx)
    }

    /// Deterministic pre-hash signing (Algorithm 23, deterministic variant).
    pub fn sign_prehashed(
        &self,
        digest: PreHashed<'_>,
        ctx: Context<'_>,
    ) -> Result<Signature<P>, Error> {
        self.sign_prehash(None, digest, ctx)
    }
}
