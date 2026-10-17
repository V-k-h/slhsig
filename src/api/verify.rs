//! Signature verification: Algorithms 24 (pure) and 25 (pre-hash).

use super::context::{Context, PreHashed};
use super::error::VerificationError;
use super::keys::VerifyingKey;
use super::sign::{PREHASH, PURE};
use super::signature::Signature;
use crate::hash::MsgParts;
use crate::params::ParameterSet;
use crate::slh;

impl<P: ParameterSet> VerifyingKey<P> {
    pub(crate) fn verify_parts(&self, msg: MsgParts<'_>, sig: &[u8]) -> bool {
        slh::verify_internal::<P>(msg, sig, &self.pk_seed, &self.pk_root, &self.seeded)
    }

    /// Algorithm 24: verifies a pure signature on `msg` under context `ctx`.
    pub fn verify(
        &self,
        msg: &[u8],
        ctx: Context<'_>,
        sig: &Signature<P>,
    ) -> Result<(), VerificationError> {
        // 4: M' <- toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
        let head = [PURE, ctx.len_byte()];
        let parts: [&[u8]; 3] = [&head, ctx.as_bytes(), msg];
        // 5: return slh_verify_internal(M', SIG, PK)
        if self.verify_parts(MsgParts(&parts), sig.as_bytes()) {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }

    /// Algorithm 24 on an unparsed signature. Any length other than `P::SIG_BYTES` fails.
    pub fn verify_bytes(
        &self,
        msg: &[u8],
        ctx: Context<'_>,
        sig: &[u8],
    ) -> Result<(), VerificationError> {
        let sig = Signature::<P>::from_slice(sig).map_err(|_| VerificationError)?;
        self.verify(msg, ctx, &sig)
    }

    /// Algorithm 25: verifies a pre-hash signature over `digest` under context `ctx`.
    ///
    /// Fails for SHA-256 or SHAKE128 digests with category 3 and 5 parameter sets, which this
    /// crate never produces (FIPS 205 §10.2.2).
    pub fn verify_prehashed(
        &self,
        digest: PreHashed<'_>,
        ctx: Context<'_>,
        sig: &Signature<P>,
    ) -> Result<(), VerificationError> {
        if !digest.alg().suits_category(P::CATEGORY) {
            return Err(VerificationError);
        }
        // 20: M' <- toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH_M
        let head = [PREHASH, ctx.len_byte()];
        let parts: [&[u8]; 4] = [&head, ctx.as_bytes(), digest.alg().oid_der(), digest.digest()];
        // 21: return slh_verify_internal(M', SIG, PK)
        if self.verify_parts(MsgParts(&parts), sig.as_bytes()) {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}
