//! Optional integrations: RustCrypto `signature` traits and `serde`.

#[cfg(feature = "signature-traits")]
mod signature_traits {
    use crate::api::{
        Context, Deterministic, Hedged, Signature, SigningKey, Variant, VerifyingKey,
    };
    use crate::params::ParameterSet;
    use alloc::boxed::Box;
    use rand_core::TryCryptoRng;
    use signature::{Error, Keypair, RandomizedSigner, SignatureEncoding, Signer, Verifier};

    // The `signature` traits carry no context string, so every impl here is pure SLH-DSA with
    // the empty context. Use the inherent methods for contexts and pre-hash signing.

    impl<P: ParameterSet> From<Signature<P>> for Box<[u8]> {
        fn from(sig: Signature<P>) -> Self {
            sig.into_bytes()
        }
    }

    impl<P: ParameterSet> SignatureEncoding for Signature<P> {
        type Repr = Box<[u8]>;
    }

    impl<P: ParameterSet> Signer<Signature<P>> for SigningKey<P, Deterministic> {
        fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, Error> {
            self.sign(msg, Context::EMPTY).map_err(|_| Error::new())
        }
    }

    impl<P: ParameterSet> RandomizedSigner<Signature<P>> for SigningKey<P, Hedged> {
        fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
            &self,
            rng: &mut R,
            msg: &[u8],
        ) -> Result<Signature<P>, Error> {
            SigningKey::try_sign(self, rng, msg, Context::EMPTY).map_err(|_| Error::new())
        }
    }

    impl<P: ParameterSet> Verifier<Signature<P>> for VerifyingKey<P> {
        fn verify(&self, msg: &[u8], signature: &Signature<P>) -> Result<(), Error> {
            VerifyingKey::verify(self, msg, Context::EMPTY, signature).map_err(|_| Error::new())
        }
    }

    impl<P: ParameterSet, V: Variant> Keypair for SigningKey<P, V> {
        type VerifyingKey = VerifyingKey<P>;
        fn verifying_key(&self) -> VerifyingKey<P> {
            SigningKey::verifying_key(self)
        }
    }
}

#[cfg(feature = "serde")]
mod serde_impls {
    use crate::api::{Signature, VerifyingKey};
    use crate::params::ParameterSet;
    use alloc::vec::Vec;
    use core::fmt;
    use core::marker::PhantomData;
    use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
    use serde::ser::{Serialize, Serializer};

    // Public keys and signatures serialize as their raw FIPS 205 bytes. Secret keys have no
    // serde support: export them explicitly with `SigningKey::to_bytes`.

    struct BytesVisitor<T>(PhantomData<T>);

    impl<'de, T: TryFrom<Vec<u8>>> Visitor<'de> for BytesVisitor<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("SLH-DSA bytes of the parameter set's exact length")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<T, E> {
            T::try_from(v.to_vec()).map_err(|_| E::invalid_length(v.len(), &self))
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<T, E> {
            let len = v.len();
            T::try_from(v).map_err(|_| E::invalid_length(len, &self))
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<T, A::Error> {
            let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64 * 1024));
            while let Some(b) = seq.next_element::<u8>()? {
                v.push(b);
            }
            self.visit_byte_buf(v)
        }
    }

    impl<P: ParameterSet> TryFrom<Vec<u8>> for VerifyingKey<P> {
        type Error = crate::api::Error;
        fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
            VerifyingKey::from_slice(&v)
        }
    }

    impl<P: ParameterSet> TryFrom<Vec<u8>> for Signature<P> {
        type Error = crate::api::Error;
        fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
            Signature::from_vec(v)
        }
    }

    impl<P: ParameterSet> Serialize for VerifyingKey<P> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.to_bytes().as_ref())
        }
    }

    impl<'de, P: ParameterSet> Deserialize<'de> for VerifyingKey<P> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_bytes(BytesVisitor(PhantomData))
        }
    }

    impl<P: ParameterSet> Serialize for Signature<P> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(self.as_bytes())
        }
    }

    impl<'de, P: ParameterSet> Deserialize<'de> for Signature<P> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_bytes(BytesVisitor(PhantomData))
        }
    }
}
