use std::convert::{TryFrom, TryInto};

#[cfg(not(feature = "openssl"))]
use p256::NistP256;
#[cfg(not(feature = "openssl"))]
use p384::NistP384;
#[cfg(not(feature = "openssl"))]
use p521::NistP521;
use pkcs8::{PrivateKeyInfoRef, SecretDocument};
#[cfg(not(feature = "openssl"))]
use pkcs8::{AssociatedOid, EncodePrivateKey};
use spki::ObjectIdentifier;
use ssh_key::PrivateKey;
use ssh_key::private::{EcdsaKeypair, KeypairData};
#[cfg(not(feature = "openssl"))]
use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};

use crate::keys::Error;
#[cfg(not(feature = "openssl"))]
use crate::keys::key::safe_rng;

// NIST curve OIDs (SEC2 / RFC 5480), hardcoded here instead of read via the
// `p256`/`p384`/`p521` crates' `AssociatedOid` impls so curve identification
// doesn't depend on which backend feature is selected; the actual OID
// values are identical either way.
mod oid {
    use spki::ObjectIdentifier;

    pub(super) const NIST_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    pub(super) const NIST_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
    pub(super) const NIST_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
    /// RFC 8410 Ed25519 algorithm OID, used by the `openssl` backend instead
    /// of `ed25519_dalek::pkcs8::ALGORITHM_OID`.
    #[cfg(feature = "openssl")]
    pub(super) const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
}

/// Decode a PKCS#8-encoded private key (ASN.1 or X9.62)
pub fn decode_pkcs8(
    ciphertext: &[u8],
    password: Option<&[u8]>,
) -> Result<ssh_key::PrivateKey, Error> {
    let doc = if let Some(password) = password {
        // OpenSSL decrypts (PBES1/PBES2, any cipher it supports) and
        // re-encodes as a plain PKCS#8 `PrivateKeyInfo`, so the rest of this
        // function's parsing is unchanged either way.
        #[cfg(feature = "openssl")]
        {
            let pkey = openssl::pkey::PKey::private_key_from_pkcs8_passphrase(ciphertext, password)
                .map_err(|_| Error::CouldNotReadKey)?;
            let der = pkey
                .private_key_to_pkcs8()
                .map_err(|_| Error::CouldNotReadKey)?;
            SecretDocument::try_from(der.as_slice())?
        }
        #[cfg(not(feature = "openssl"))]
        {
            SecretDocument::try_from(ciphertext)?
                .decode_msg::<pkcs8::EncryptedPrivateKeyInfoRef<'_>>()?
                .decrypt(password)?
        }
    } else {
        SecretDocument::try_from(ciphertext)?
    };

    if let Ok(key) = doc.decode_msg::<sec1::EcPrivateKey>() {
        // X9.62 EC private key
        let Some(curve) = key.parameters.and_then(|x| x.named_curve()) else {
            return Err(Error::CouldNotReadKey);
        };
        #[cfg(feature = "openssl")]
        let kp = openssl_backend::ec_keypair_from_sec1(curve, key)?;
        #[cfg(not(feature = "openssl"))]
        let kp = ec_key_data_into_keypair(curve, key)?;
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // SEC1 key with full domain parameters (not a named curve OID)
    if let Ok(kp) = explicit_curve_params::decode_sec1_with_full_domain_params(ciphertext) {
        return Ok(PrivateKey::new(KeypairData::Ecdsa(kp), "")?);
    }

    // ASN.1 key (PKCS#8)
    Ok(pkcs8_pki_into_keypair_data(doc.decode_msg::<PrivateKeyInfoRef<'_>>()?)?.try_into()?)
}

fn pkcs8_pki_into_keypair_data(pki: PrivateKeyInfoRef<'_>) -> Result<KeypairData, Error> {
    // Temporary if {} due to multiple const_oid crate versions
    #[cfg(all(feature = "rsa", feature = "openssl"))]
    if pki.algorithm.oid.as_bytes() == pkcs1::ALGORITHM_OID.as_bytes() {
        let sk = &pkcs1::RsaPrivateKeyRef::try_from(pki.private_key)?;
        return Ok(KeypairData::Rsa(openssl_backend::rsa_keypair_from_pkcs1(sk)?));
    }

    #[cfg(all(feature = "rsa", not(feature = "openssl")))]
    if pki.algorithm.oid.as_bytes() == pkcs1::ALGORITHM_OID.as_bytes() {
        let sk = &pkcs1::RsaPrivateKeyRef::try_from(pki.private_key)?;
        let pk = rsa::PrivateKey::from_components(
            rsa::BoxedUint::from_be_slice_vartime(sk.modulus.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.public_exponent.as_bytes()),
            rsa::BoxedUint::from_be_slice_vartime(sk.private_exponent.as_bytes()),
            vec![
                rsa::BoxedUint::from_be_slice_vartime(sk.prime1.as_bytes()),
                rsa::BoxedUint::from_be_slice_vartime(sk.prime2.as_bytes()),
            ],
        )?;
        return Ok(KeypairData::Rsa(pk.try_into()?));
    }

    #[cfg(feature = "openssl")]
    {
        if pki.algorithm.oid.as_bytes() == oid::ED25519.as_bytes() {
            return Ok(KeypairData::Ed25519(openssl_backend::ed25519_keypair_from_pkcs8(
                pki.private_key.as_bytes(),
            )?));
        }
        if pki.algorithm.oid.as_bytes() == sec1::ALGORITHM_OID.as_bytes() {
            let curve_oid = pki.algorithm.parameters_oid()?;
            let sec1_key = sec1::EcPrivateKey::try_from(pki.private_key.as_bytes())?;
            return Ok(KeypairData::Ecdsa(openssl_backend::ec_keypair_from_sec1(
                curve_oid, sec1_key,
            )?));
        }
        return Err(Error::UnknownAlgorithm(pki.algorithm.oid));
    }

    #[cfg(not(feature = "openssl"))]
    match pki.algorithm.oid {
        ed25519_dalek::pkcs8::ALGORITHM_OID => {
            let kpb = ed25519_dalek::pkcs8::KeypairBytes::try_from(pki)?;
            let pk = Ed25519PrivateKey::from_bytes(&kpb.secret_key);
            Ok(KeypairData::Ed25519(Ed25519Keypair {
                public: pk.clone().into(),
                private: pk,
            }))
        }
        sec1::ALGORITHM_OID => Ok(KeypairData::Ecdsa(ec_key_data_into_keypair(
            pki.algorithm.parameters_oid()?,
            pki,
        )?)),
        oid => Err(Error::UnknownAlgorithm(oid)),
    }
}

#[cfg(not(feature = "openssl"))]
fn ec_key_data_into_keypair<K, E>(
    curve_oid: ObjectIdentifier,
    private_key: K,
) -> Result<EcdsaKeypair, Error>
where
    p256::SecretKey: TryFrom<K, Error = E>,
    p384::SecretKey: TryFrom<K, Error = E>,
    p521::SecretKey: TryFrom<K, Error = E>,
    crate::keys::Error: From<E>,
{
    Ok(match curve_oid {
        NistP256::OID => {
            let sk = p256::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP384::OID => {
            let sk = p384::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        NistP521::OID => {
            let sk = p521::SecretKey::try_from(private_key)?;
            EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            }
        }
        oid => return Err(Error::UnknownAlgorithm(oid)),
    })
}

// OpenSSL-backed PKCS#8 decode/encode for EC and Ed25519 keys, as an
// alternative to the `p256`/`p384`/`p521`/`ed25519-dalek` crates used above.
// `curve25519-dalek` is also gone from the `openssl`-only build (see
// kex/x25519.rs), but `p256`/`p384`/`p521`/`ecdsa` remain hard dependencies
// for the NIST-curve KEX (`kex/ecdh_nistp.rs`), which has no OpenSSL backend
// yet.
#[cfg(feature = "openssl")]
mod openssl_backend {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
    use openssl::nid::Nid;
    use openssl::pkey::{Id, PKey};
    use spki::ObjectIdentifier;
    use ssh_key::private::{EcdsaKeypair, EcdsaPrivateKey, Ed25519Keypair, Ed25519PrivateKey};

    use super::oid;
    use crate::keys::Error;

    fn nid_for_curve_oid(curve_oid: ObjectIdentifier) -> Result<Nid, Error> {
        Ok(match curve_oid {
            oid::NIST_P256 => Nid::X9_62_PRIME256V1,
            oid::NIST_P384 => Nid::SECP384R1,
            oid::NIST_P521 => Nid::SECP521R1,
            oid => return Err(Error::UnknownAlgorithm(oid)),
        })
    }

    /// Pad `bn` to exactly `N` big-endian bytes and wrap it as an
    /// [`EcdsaPrivateKey`].
    fn padded_private_key<const N: usize>(bn: &BigNum) -> Result<EcdsaPrivateKey<N>, Error> {
        let padded = bn.to_vec_padded(N as i32).map_err(|_| Error::CouldNotReadKey)?;
        let array: [u8; N] = padded.try_into().map_err(|_| Error::CouldNotReadKey)?;
        Ok(EcdsaPrivateKey::<N>::from(array))
    }

    /// Build an [`EcdsaKeypair`] from a private scalar and an optional SEC1
    /// public point, deriving the public point via `generator * private`
    /// when the caller doesn't already have it.
    fn ec_keypair_from_scalar(
        curve_oid: ObjectIdentifier,
        private_key_bytes: &[u8],
        public_key_bytes: Option<&[u8]>,
    ) -> Result<EcdsaKeypair, Error> {
        let nid = nid_for_curve_oid(curve_oid)?;
        let group = EcGroup::from_curve_name(nid).map_err(|_| Error::CouldNotReadKey)?;
        let mut ctx = BigNumContext::new().map_err(|_| Error::CouldNotReadKey)?;
        let priv_bn = BigNum::from_slice(private_key_bytes).map_err(|_| Error::CouldNotReadKey)?;

        let pub_point = if let Some(bytes) = public_key_bytes {
            EcPoint::from_bytes(&group, bytes, &mut ctx).map_err(|_| Error::CouldNotReadKey)?
        } else {
            let mut point = EcPoint::new(&group).map_err(|_| Error::CouldNotReadKey)?;
            point
                .mul_generator2(&group, &priv_bn, &mut ctx)
                .map_err(|_| Error::CouldNotReadKey)?;
            point
        };
        let pub_bytes = pub_point
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|_| Error::CouldNotReadKey)?;

        Ok(match curve_oid {
            oid::NIST_P256 => EcdsaKeypair::NistP256 {
                public: sec1::EncodedPoint::from_bytes(&pub_bytes)?,
                private: padded_private_key::<32>(&priv_bn)?,
            },
            oid::NIST_P384 => EcdsaKeypair::NistP384 {
                public: sec1::EncodedPoint::from_bytes(&pub_bytes)?,
                private: padded_private_key::<48>(&priv_bn)?,
            },
            oid::NIST_P521 => EcdsaKeypair::NistP521 {
                public: sec1::EncodedPoint::from_bytes(&pub_bytes)?,
                private: padded_private_key::<66>(&priv_bn)?,
            },
            oid => return Err(Error::UnknownAlgorithm(oid)),
        })
    }

    /// Build an [`EcdsaKeypair`] from a parsed SEC1 `EcPrivateKey` (used both
    /// for the top-level X9.62 format and for a PKCS#8-wrapped EC key, whose
    /// `privateKey` field is itself a nested DER-encoded `EcPrivateKey`).
    pub(super) fn ec_keypair_from_sec1(
        curve_oid: ObjectIdentifier,
        key: sec1::EcPrivateKey<'_>,
    ) -> Result<EcdsaKeypair, Error> {
        ec_keypair_from_scalar(curve_oid, key.private_key, key.public_key)
    }

    /// Build an [`EcdsaKeypair`] from a raw private scalar with no embedded
    /// public key (the "explicit domain params" SEC1 format never embeds one).
    pub(super) fn ec_keypair_from_raw_scalar(
        curve_oid: ObjectIdentifier,
        private_key_bytes: &[u8],
    ) -> Result<EcdsaKeypair, Error> {
        ec_keypair_from_scalar(curve_oid, private_key_bytes, None)
    }

    /// Build an [`ssh_key::private::RsaKeypair`] from a parsed PKCS#1
    /// `RsaPrivateKey`. `ssh_key`'s own `RsaPrivateKey`/`RsaPublicKey` only
    /// store big-endian byte strings (`Mpint`), so this needs no RustCrypto
    /// `rsa` crate type for storage; `RSA_check_key` gives the same
    /// consistency validation (n = p*q, d*e ≡ 1 mod lcm(p-1,q-1), CRT
    /// params match) that the RustCrypto backend's `rsa::PrivateKey::
    /// from_components` performs internally.
    #[cfg(feature = "rsa")]
    pub(super) fn rsa_keypair_from_pkcs1(
        sk: &pkcs1::RsaPrivateKeyRef<'_>,
    ) -> Result<ssh_key::private::RsaKeypair, Error> {
        use openssl::rsa::Rsa;

        let bn = |bytes: &[u8]| BigNum::from_slice(bytes).map_err(|_| Error::CouldNotReadKey);
        let rsa = Rsa::from_private_components(
            bn(sk.modulus.as_bytes())?,
            bn(sk.public_exponent.as_bytes())?,
            bn(sk.private_exponent.as_bytes())?,
            bn(sk.prime1.as_bytes())?,
            bn(sk.prime2.as_bytes())?,
            bn(sk.exponent1.as_bytes())?,
            bn(sk.exponent2.as_bytes())?,
            bn(sk.coefficient.as_bytes())?,
        )
        .map_err(|_| Error::CouldNotReadKey)?;
        if !rsa.check_key().unwrap_or(false) {
            return Err(Error::CouldNotReadKey);
        }

        let public = ssh_key::public::RsaPublicKey::new(
            ssh_key::Mpint::from_positive_bytes(sk.public_exponent.as_bytes()),
            ssh_key::Mpint::from_positive_bytes(sk.modulus.as_bytes()),
        )?;
        let private = ssh_key::private::RsaPrivateKey::new(
            ssh_key::Mpint::from_positive_bytes(sk.private_exponent.as_bytes()),
            ssh_key::Mpint::from_positive_bytes(sk.coefficient.as_bytes()),
            ssh_key::Mpint::from_positive_bytes(sk.prime1.as_bytes()),
            ssh_key::Mpint::from_positive_bytes(sk.prime2.as_bytes()),
        )?;
        Ok(ssh_key::private::RsaKeypair::new(public, private)?)
    }

    /// RSA CRT exponents (`dp`, `dq`), not stored by
    /// `ssh_key::private::RsaPrivateKey`. Same derivation
    /// `ssh-key`'s own OpenSSL signing backend uses in `signature.rs`.
    #[cfg(feature = "rsa")]
    fn rsa_calc_dp_dq(
        d: &openssl::bn::BigNumRef,
        p: &openssl::bn::BigNumRef,
        q: &openssl::bn::BigNumRef,
    ) -> Result<(BigNum, BigNum), Error> {
        let one = BigNum::from_u32(1).map_err(|_| Error::CouldNotReadKey)?;
        let p1 = p - one.as_ref();
        let q1 = q - one.as_ref();
        let mut ctx = BigNumContext::new().map_err(|_| Error::CouldNotReadKey)?;
        let mut dp = BigNum::new().map_err(|_| Error::CouldNotReadKey)?;
        let mut dq = BigNum::new().map_err(|_| Error::CouldNotReadKey)?;
        dp.checked_rem(d, &p1, &mut ctx)
            .map_err(|_| Error::CouldNotReadKey)?;
        dq.checked_rem(d, &q1, &mut ctx)
            .map_err(|_| Error::CouldNotReadKey)?;
        Ok((dp, dq))
    }

    /// Encode an [`ssh_key::private::RsaKeypair`] as a PKCS#8 DER document.
    #[cfg(feature = "rsa")]
    pub(super) fn rsa_keypair_to_pkcs8_der(
        keypair: &ssh_key::private::RsaKeypair,
    ) -> Result<Vec<u8>, Error> {
        use openssl::rsa::Rsa;

        let bn = |mpint: &ssh_key::Mpint| {
            BigNum::from_slice(mpint.as_positive_bytes().ok_or(Error::CouldNotReadKey)?)
                .map_err(|_| Error::CouldNotReadKey)
        };
        let n = bn(keypair.public().n())?;
        let e = bn(keypair.public().e())?;
        let d = bn(keypair.private().d())?;
        let p = bn(keypair.private().p())?;
        let q = bn(keypair.private().q())?;
        let iqmp = bn(keypair.private().iqmp())?;
        let (dp, dq) = rsa_calc_dp_dq(&d, &p, &q)?;

        let rsa = Rsa::from_private_components(n, e, d, p, q, dp, dq, iqmp)
            .map_err(|_| Error::CouldNotReadKey)?;
        let pkey = PKey::from_rsa(rsa).map_err(|_| Error::CouldNotReadKey)?;
        pkey.private_key_to_pkcs8().map_err(|_| Error::CouldNotReadKey)
    }

    /// RFC 8410 §7: an Ed25519 PKCS#8 `privateKey` OCTET STRING contains a
    /// nested OCTET STRING (tag `0x04`, length `0x20`) wrapping the raw
    /// 32-byte seed -- fixed structure, no DER library needed to unwrap it.
    fn ed25519_seed_from_pkcs8_private_key(private_key: &[u8]) -> Result<[u8; 32], Error> {
        match private_key {
            [0x04, 0x20, seed @ ..] if seed.len() == 32 => {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(seed);
                Ok(bytes)
            }
            _ => Err(Error::CouldNotReadKey),
        }
    }

    pub(super) fn ed25519_keypair_from_pkcs8(private_key: &[u8]) -> Result<Ed25519Keypair, Error> {
        let seed = ed25519_seed_from_pkcs8_private_key(private_key)?;
        Ok(Ed25519Keypair::from_seed(&seed))
    }

    pub(super) fn ed25519_keypair_to_pkcs8_der(private: &Ed25519PrivateKey) -> Result<Vec<u8>, Error> {
        let pkey = PKey::private_key_from_raw_bytes(private.as_ref(), Id::ED25519)
            .map_err(|_| Error::CouldNotReadKey)?;
        pkey.private_key_to_pkcs8().map_err(|_| Error::CouldNotReadKey)
    }

    pub(super) fn ecdsa_keypair_to_pkcs8_der(pair: &EcdsaKeypair) -> Result<Vec<u8>, Error> {
        let (curve_oid, private, public) = match pair {
            EcdsaKeypair::NistP256 { private, public } => (oid::NIST_P256, private.as_slice(), public.as_bytes()),
            EcdsaKeypair::NistP384 { private, public } => (oid::NIST_P384, private.as_slice(), public.as_bytes()),
            EcdsaKeypair::NistP521 { private, public } => (oid::NIST_P521, private.as_slice(), public.as_bytes()),
        };
        let nid = nid_for_curve_oid(curve_oid)?;
        let group = EcGroup::from_curve_name(nid).map_err(|_| Error::CouldNotReadKey)?;
        let mut ctx = BigNumContext::new().map_err(|_| Error::CouldNotReadKey)?;
        let priv_bn = BigNum::from_slice(private).map_err(|_| Error::CouldNotReadKey)?;
        let pub_point = EcPoint::from_bytes(&group, public, &mut ctx).map_err(|_| Error::CouldNotReadKey)?;
        let ec_key = EcKey::from_private_components(&group, &priv_bn, &pub_point)
            .map_err(|_| Error::CouldNotReadKey)?;
        let pkey = PKey::from_ec_key(ec_key).map_err(|_| Error::CouldNotReadKey)?;
        pkey.private_key_to_pkcs8().map_err(|_| Error::CouldNotReadKey)
    }
}

mod explicit_curve_params {
    use super::*;

    use der::{
        Reader, SliceReader, Tag, TagNumber, Tagged,
        asn1::{AnyRef, ContextSpecific, UintRef},
    };

    /// Try to parse an SEC1 EC key with full domain parameters.
    ///
    /// Some key generators (e.g. OpenSSL with certain options) produce SEC1 keys
    /// where the `[0]` parameters field contains full EC domain parameters instead
    /// of a named curve OID. The `sec1` crate does not support this format.
    pub fn decode_sec1_with_full_domain_params(der_bytes: &[u8]) -> Result<EcdsaKeypair, Error> {
        let mut reader = SliceReader::new(der_bytes)?;
        reader.sequence(|seq| {
            let version: u8 = seq.decode()?;
            if version < 1 {
                return Err(Error::CouldNotReadKey);
            }

            let priv_key: AnyRef = seq.decode()?;
            priv_key.tag().assert_eq(Tag::OctetString)?;

            let params = ContextSpecific::<AnyRef>::decode_explicit(seq, TagNumber(0))?
                .ok_or(Error::CouldNotReadKey)?;

            let curve_oid = extract_curve_from_domain_params(params.value)?;

            let keypair = build_ec_keypair_from_bytes(curve_oid, priv_key.value())?;

            // Drain any remaining optional fields (e.g. [1] publicKey) so finish() succeeds
            seq.drain(seq.remaining_len())?;
            Ok(keypair)
        })
    }

    /// Extract the named curve OID from full EC domain parameters.
    /// Handles two formats:
    /// 1. Standard ECParameters: SEQUENCE { FieldID, Curve, base, order, cofactor }
    /// 2. Wrapped ECParameters: SEQUENCE { INTEGER version, SEQUENCE { FieldID, ... } }
    fn extract_curve_from_domain_params(params: AnyRef<'_>) -> Result<ObjectIdentifier, Error> {
        params.tag().assert_eq(Tag::Sequence)?;

        // Use a standalone SliceReader so we aren't required to consume all of ECParams
        // (Curve, base, order, cofactor follow FieldID but are irrelevant here).
        let mut seq = SliceReader::new(params.value())?;

        // Skip optional ECParameters version INTEGER
        if Tag::peek(&seq)? == Tag::Integer {
            seq.decode::<u8>()?;
        }

        // FieldID ::= SEQUENCE { fieldType OID, parameters ANY }
        seq.sequence(|field_id| {
            let _field_oid: ObjectIdentifier = field_id.decode()?;
            // prime INTEGER — as_bytes() strips DER sign-extension leading zero
            let prime: UintRef = field_id.decode()?;
            Ok(match prime.as_bytes().len() {
                32 => super::oid::NIST_P256,
                48 => super::oid::NIST_P384,
                66 => super::oid::NIST_P521,
                _ => return Err(Error::CouldNotReadKey),
            })
        })
    }

    /// Build an EcdsaKeypair from raw private key bytes and a curve OID.
    #[cfg(feature = "openssl")]
    fn build_ec_keypair_from_bytes(
        curve_oid: ObjectIdentifier,
        private_key_bytes: &[u8],
    ) -> Result<EcdsaKeypair, Error> {
        super::openssl_backend::ec_keypair_from_raw_scalar(curve_oid, private_key_bytes)
    }

    /// Build an EcdsaKeypair from raw private key bytes and a curve OID.
    #[cfg(not(feature = "openssl"))]
    fn build_ec_keypair_from_bytes(
        curve_oid: ObjectIdentifier,
        private_key_bytes: &[u8],
    ) -> Result<EcdsaKeypair, Error> {
        if curve_oid == NistP256::OID {
            let sk = p256::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP256 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else if curve_oid == NistP384::OID {
            let sk = p384::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP384 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else if curve_oid == NistP521::OID {
            let sk = p521::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| Error::CouldNotReadKey)?;
            Ok(EcdsaKeypair::NistP521 {
                public: sk.public_key().into(),
                private: sk.into(),
            })
        } else {
            Err(Error::UnknownAlgorithm(curve_oid))
        }
    }
}

/// Encode into a password-protected PKCS#8-encoded private key.
///
/// `rounds` only applies to the non-`openssl` backends; OpenSSL's
/// `PKey::private_key_to_pkcs8_passphrase` has no equivalent knob and uses
/// its own library default PBKDF2 iteration count.
pub fn encode_pkcs8_encrypted(
    pass: &[u8],
    rounds: u32,
    key: &PrivateKey,
) -> Result<Vec<u8>, Error> {
    let pvi_bytes = encode_pkcs8(key)?;

    #[cfg(feature = "openssl")]
    {
        let _ = rounds;
        let pkey = openssl::pkey::PKey::private_key_from_pkcs8(&pvi_bytes)
            .map_err(|_| Error::CouldNotReadKey)?;
        pkey.private_key_to_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), pass)
            .map_err(|_| Error::InvalidParameters)
    }
    #[cfg(not(feature = "openssl"))]
    {
        let pvi = PrivateKeyInfoRef::try_from(pvi_bytes.as_slice())?;

        use rand_core::Rng;
        let mut rng = safe_rng();
        let mut salt = [0; 32];
        rng.fill_bytes(&mut salt);
        let mut iv = [0; 16];
        rng.fill_bytes(&mut iv);

        let doc = pvi.encrypt_with_params(
            pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(rounds, &salt, iv)
                .map_err(|_| Error::InvalidParameters)?,
            pass,
        )?;
        Ok(doc.as_bytes().to_vec())
    }
}

/// Encode into a PKCS#8-encoded private key.
pub fn encode_pkcs8(key: &ssh_key::PrivateKey) -> Result<Vec<u8>, Error> {
    let v = match key.key_data() {
        #[cfg(feature = "openssl")]
        ssh_key::private::KeypairData::Ed25519(pair) => {
            openssl_backend::ed25519_keypair_to_pkcs8_der(&pair.private)?
        }
        #[cfg(not(feature = "openssl"))]
        ssh_key::private::KeypairData::Ed25519(pair) => {
            let sk: ed25519_dalek::SigningKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        #[cfg(all(feature = "rsa", feature = "openssl"))]
        ssh_key::private::KeypairData::Rsa(pair) => openssl_backend::rsa_keypair_to_pkcs8_der(pair)?,
        #[cfg(all(feature = "rsa", not(feature = "openssl")))]
        ssh_key::private::KeypairData::Rsa(pair) => {
            use rsa::pkcs8::EncodePrivateKey;
            let sk: rsa::PrivateKey = pair.try_into()?;
            sk.to_pkcs8_der()?.as_bytes().to_vec()
        }
        #[cfg(feature = "openssl")]
        ssh_key::private::KeypairData::Ecdsa(pair) => openssl_backend::ecdsa_keypair_to_pkcs8_der(pair)?,
        #[cfg(not(feature = "openssl"))]
        ssh_key::private::KeypairData::Ecdsa(pair) => match pair {
            EcdsaKeypair::NistP256 { private, .. } => {
                let sk = p256::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP384 { private, .. } => {
                let sk = p384::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
            EcdsaKeypair::NistP521 { private, .. } => {
                let sk = p521::SecretKey::from_slice(private.as_slice())?;
                sk.to_pkcs8_der()?.as_bytes().to_vec()
            }
        },
        _ => {
            let algo = key.algorithm();
            let kt = algo.as_str();
            return Err(Error::UnsupportedKeyType {
                key_type_string: kt.into(),
                key_type_raw: kt.as_bytes().into(),
            });
        }
    };
    Ok(v)
}
