use super::context::{FaultCheck, KeyUsage};
use super::error::Error;
use crate::hash::{ByteArray, HashSuite};
use crate::params::{NodeOf, ParameterSet, SeededOf};
use crate::slh;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, Zeroizing};

mod sealed {
    pub trait Variant {}
}

/// The signing variant a key is bound to (FIPS 205 §9.2, §10.1: one variant per key).
pub trait Variant: sealed::Variant + Send + Sync + 'static {
    #[doc(hidden)]
    const DETERMINISTIC: bool;
}

/// Hedged signing: fresh n-byte randomness per signature. FIPS 205's default and this crate's.
#[derive(Debug)]
pub enum Hedged {}

/// Deterministic signing: PK.seed replaces the per-signature randomness.
#[derive(Debug)]
pub enum Deterministic {}

impl sealed::Variant for Hedged {}
impl sealed::Variant for Deterministic {}
impl Variant for Hedged {
    const DETERMINISTIC: bool = false;
}
impl Variant for Deterministic {
    const DETERMINISTIC: bool = true;
}

/// An SLH-DSA public key: `PK.seed || PK.root`.
pub struct VerifyingKey<P: ParameterSet> {
    pub(crate) pk_seed: NodeOf<P>,
    pub(crate) pk_root: NodeOf<P>,
    pub(crate) seeded: SeededOf<P>,
}

impl<P: ParameterSet> VerifyingKey<P> {
    pub(crate) fn from_parts(pk_seed: NodeOf<P>, pk_root: NodeOf<P>) -> Self {
        let seeded = P::Hash::seed(&pk_seed);
        Self { pk_seed, pk_root, seeded }
    }

    /// Decodes a public key. Every 2n-byte string is a well-formed public key.
    pub fn from_bytes(pk: &P::PkBytes) -> Self {
        let (seed, root) = pk.as_ref().split_at(P::N);
        Self::from_parts(NodeOf::<P>::copy_from(seed), NodeOf::<P>::copy_from(root))
    }

    /// Decodes a public key from a slice, rejecting any length other than `P::PK_BYTES`.
    pub fn from_slice(pk: &[u8]) -> Result<Self, Error> {
        if pk.len() != P::PK_BYTES {
            return Err(Error::InvalidKeyLength);
        }
        Ok(Self::from_bytes(&P::PkBytes::copy_from(pk)))
    }

    /// Encodes the public key as `PK.seed || PK.root`.
    pub fn to_bytes(&self) -> P::PkBytes {
        let mut out = P::PkBytes::zeroed();
        out.as_mut()[..P::N].copy_from_slice(self.pk_seed.as_ref());
        out.as_mut()[P::N..].copy_from_slice(self.pk_root.as_ref());
        out
    }
}

impl<P: ParameterSet> Clone for VerifyingKey<P> {
    fn clone(&self) -> Self {
        Self { pk_seed: self.pk_seed, pk_root: self.pk_root, seeded: self.seeded.clone() }
    }
}

impl<P: ParameterSet> PartialEq for VerifyingKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.pk_seed == other.pk_seed && self.pk_root == other.pk_root
    }
}

impl<P: ParameterSet> Eq for VerifyingKey<P> {}

impl<P: ParameterSet> Hash for VerifyingKey<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pk_seed.as_ref().hash(state);
        self.pk_root.as_ref().hash(state);
    }
}

impl<P: ParameterSet> fmt::Debug for VerifyingKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey<{}>(", P::NAME)?;
        for b in self.to_bytes().as_ref() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// SK.seed and SK.prf, zeroized on drop.
struct SecretSeeds<P: ParameterSet> {
    sk_seed: NodeOf<P>,
    sk_prf: NodeOf<P>,
}

impl<P: ParameterSet> Drop for SecretSeeds<P> {
    fn drop(&mut self) {
        self.sk_seed.zeroize();
        self.sk_prf.zeroize();
    }
}

/// An SLH-DSA secret key, bound to one signing variant `V` and one [`KeyUsage`].
///
/// Secret seeds are zeroized on drop. The key implements neither `Clone` nor `PartialEq`,
/// and its `Debug` output contains no key material.
pub struct SigningKey<P: ParameterSet, V: Variant = Hedged> {
    secret: SecretSeeds<P>,
    vk: VerifyingKey<P>,
    usage: KeyUsage,
    fault_check: FaultCheck,
    _variant: PhantomData<V>,
}

impl<P: ParameterSet, V: Variant> SigningKey<P, V> {
    /// Algorithm 18 from caller-supplied seeds. PK.root is always computed here.
    pub(crate) fn from_seed_nodes(
        sk_seed: NodeOf<P>,
        sk_prf: NodeOf<P>,
        pk_seed: NodeOf<P>,
    ) -> Self {
        let seeded = P::Hash::seed(&pk_seed);
        let pk_root = slh::keygen_internal::<P>(&sk_seed, &seeded);
        Self {
            secret: SecretSeeds { sk_seed, sk_prf },
            vk: VerifyingKey { pk_seed, pk_root, seeded },
            usage: KeyUsage::Pure,
            fault_check: FaultCheck::default(),
            _variant: PhantomData,
        }
    }

    /// Algorithm 21: generates a key pair with SK.seed, SK.prf and PK.seed drawn from `rng`.
    ///
    /// `rng` must be a cryptographically secure generator with at least 8n bits of security.
    pub fn try_generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, Error> {
        let mut seeds = Zeroizing::new([NodeOf::<P>::zeroed(); 3]);
        for seed in seeds.iter_mut() {
            rng.try_fill_bytes(seed.as_mut()).map_err(|_| Error::Entropy)?;
        }
        Ok(Self::from_seed_nodes(seeds[0], seeds[1], seeds[2]))
    }

    /// Generates a key pair from the operating system's entropy source (`getrandom::SysRng`).
    #[cfg(feature = "os-rng")]
    pub fn generate() -> Result<Self, Error> {
        Self::try_generate(&mut getrandom::SysRng)
    }

    /// Decodes a secret key and checks it: PK.root is recomputed from SK.seed and PK.seed, and a
    /// mismatch returns [`Error::InconsistentKey`]. This costs as much as key generation.
    pub fn from_bytes(sk: &P::SkBytes) -> Result<Self, Error> {
        let stored_root = NodeOf::<P>::copy_from(&sk.as_ref()[3 * P::N..]);
        let key = Self::from_bytes_unchecked(sk);
        let recomputed = slh::keygen_internal::<P>(&key.secret.sk_seed, &key.vk.seeded);
        // PK.root is public, so the comparison need not be constant time.
        if recomputed == stored_root { Ok(key) } else { Err(Error::InconsistentKey) }
    }

    /// Decodes and checks a secret key from a slice of exactly `P::SK_BYTES` bytes.
    pub fn from_slice(sk: &[u8]) -> Result<Self, Error> {
        if sk.len() != P::SK_BYTES {
            return Err(Error::InvalidKeyLength);
        }
        let sk = Zeroizing::new(P::SkBytes::copy_from(sk));
        Self::from_bytes(&sk)
    }

    /// Decodes a secret key without recomputing PK.root. For key stores that already
    /// authenticate their blobs; the default fault check still rejects a bad key at first use.
    pub fn from_bytes_unchecked(sk: &P::SkBytes) -> Self {
        let n = P::N;
        let b = sk.as_ref();
        let pk_seed = NodeOf::<P>::copy_from(&b[2 * n..3 * n]);
        Self {
            secret: SecretSeeds {
                sk_seed: NodeOf::<P>::copy_from(&b[..n]),
                sk_prf: NodeOf::<P>::copy_from(&b[n..2 * n]),
            },
            vk: VerifyingKey::from_parts(pk_seed, NodeOf::<P>::copy_from(&b[3 * n..])),
            usage: KeyUsage::Pure,
            fault_check: FaultCheck::default(),
            _variant: PhantomData,
        }
    }

    /// Encodes the secret key as `SK.seed || SK.prf || PK.seed || PK.root`.
    pub fn to_bytes(&self) -> Zeroizing<P::SkBytes> {
        let n = P::N;
        let mut out = Zeroizing::new(P::SkBytes::zeroed());
        let b = out.as_mut();
        b[..n].copy_from_slice(self.secret.sk_seed.as_ref());
        b[n..2 * n].copy_from_slice(self.secret.sk_prf.as_ref());
        b[2 * n..3 * n].copy_from_slice(self.vk.pk_seed.as_ref());
        b[3 * n..].copy_from_slice(self.vk.pk_root.as_ref());
        out
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey<P> {
        self.vk.clone()
    }

    /// The matching public key, borrowed.
    pub fn as_verifying_key(&self) -> &VerifyingKey<P> {
        &self.vk
    }

    /// What this key may sign.
    pub fn usage(&self) -> KeyUsage {
        self.usage
    }

    /// Restricts the key to pure signing or to pre-hash signing with one hash function.
    /// Rejects SHA-256 and SHAKE128 for category 3 and 5 sets ([`Error::PreHashTooWeak`]).
    pub fn set_usage(&mut self, usage: KeyUsage) -> Result<(), Error> {
        if let KeyUsage::PreHash(alg) = usage
            && !alg.suits_category(P::CATEGORY)
        {
            return Err(Error::PreHashTooWeak);
        }
        self.usage = usage;
        Ok(())
    }

    /// The fault check applied to every signature.
    pub fn fault_check(&self) -> FaultCheck {
        self.fault_check
    }

    /// Changes the fault check applied to every signature.
    pub fn set_fault_check(&mut self, mode: FaultCheck) {
        self.fault_check = mode;
    }

    /// Builder form of [`set_fault_check`](Self::set_fault_check).
    pub fn with_fault_check(mut self, mode: FaultCheck) -> Self {
        self.fault_check = mode;
        self
    }

    pub(crate) fn sign_inputs(&self) -> slh::SignInputs<'_, P> {
        slh::SignInputs {
            sk_seed: &self.secret.sk_seed,
            sk_prf: &self.secret.sk_prf,
            pk_seed: &self.vk.pk_seed,
            pk_root: &self.vk.pk_root,
            seeded: &self.vk.seeded,
        }
    }
}

impl<P: ParameterSet, V: Variant> fmt::Debug for SigningKey<P, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("parameter_set", &P::NAME)
            .field("deterministic", &V::DETERMINISTIC)
            .field("usage", &self.usage)
            .field("fault_check", &self.fault_check)
            .finish_non_exhaustive()
    }
}
