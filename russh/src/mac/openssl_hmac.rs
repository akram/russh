//! HMAC-SHA1/SHA2-256/512 (and their `-etm@openssh.com` variants) via
//! system OpenSSL, for environments that require all cryptographic
//! operations to go through a FIPS-certifiable OpenSSL build.
//!
//! `hmac-sha1`/`hmac-sha1-etm` are legacy/deprecated algorithms, but
//! porting them anyway (rather than leaving them RustCrypto-only) is what
//! lets this crate drop `sha1` entirely from the `openssl` feature's
//! dependency graph: `sha1` stays a RustCrypto dependency for the
//! aws-lc-rs/ring backends (unconditionally fine there, since neither of
//! those backends is FIPS-certifiable in this build anyway), but the
//! `openssl` feature no longer needs it at all once this module and the
//! legacy KEX algorithms (removed separately) stop requiring it.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use subtle::ConstantTimeEq;

use super::{Mac, MacAlgorithm};

/// `MessageDigest::sha256()`/`sha512()` aren't `const fn` (they wrap an FFI
/// lookup), so the static `_HMAC_SHA256`/`_HMAC_SHA512` tables store this
/// instead and resolve the real `MessageDigest` lazily.
#[derive(Clone, Copy)]
pub(crate) enum HmacDigest {
    Sha1,
    Sha256,
    Sha512,
}

impl HmacDigest {
    fn message_digest(self) -> MessageDigest {
        match self {
            HmacDigest::Sha1 => MessageDigest::sha1(),
            HmacDigest::Sha256 => MessageDigest::sha256(),
            HmacDigest::Sha512 => MessageDigest::sha512(),
        }
    }
}

pub(crate) struct OsslHmacAlgorithm {
    pub(crate) digest: HmacDigest,
    pub(crate) key_len: usize,
}

struct OsslHmac {
    key: Vec<u8>,
    digest: MessageDigest,
}

impl MacAlgorithm for OsslHmacAlgorithm {
    fn key_len(&self) -> usize {
        self.key_len
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        Box::new(OsslHmac {
            key: mac_key[..self.key_len].to_vec(),
            digest: self.digest.message_digest(),
        }) as Box<dyn Mac + Send>
    }
}

impl Mac for OsslHmac {
    fn mac_len(&self) -> usize {
        self.digest.size()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        #[allow(clippy::unwrap_used)]
        let pkey = PKey::hmac(&self.key).unwrap();
        #[allow(clippy::unwrap_used)]
        let mut signer = Signer::new(self.digest, &pkey).unwrap();
        #[allow(clippy::unwrap_used)]
        {
            signer.update(&sequence_number.to_be_bytes()).unwrap();
            signer.update(payload).unwrap();
        }
        #[allow(clippy::unwrap_used)]
        let tag = signer.sign_to_vec().unwrap();
        output.copy_from_slice(&tag);
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        let mut buf = vec![0; self.mac_len()];
        self.compute(sequence_number, payload, &mut buf);
        buf.ct_eq(mac).into()
    }
}

pub(crate) struct OsslEtmHmac(OsslHmac);

pub(crate) struct OsslEtmHmacAlgorithm {
    pub(crate) digest: HmacDigest,
    pub(crate) key_len: usize,
}

impl MacAlgorithm for OsslEtmHmacAlgorithm {
    fn key_len(&self) -> usize {
        self.key_len
    }

    fn make_mac(&self, mac_key: &[u8]) -> Box<dyn Mac + Send> {
        Box::new(OsslEtmHmac(OsslHmac {
            key: mac_key[..self.key_len].to_vec(),
            digest: self.digest.message_digest(),
        })) as Box<dyn Mac + Send>
    }
}

impl Mac for OsslEtmHmac {
    fn is_etm(&self) -> bool {
        true
    }

    fn mac_len(&self) -> usize {
        self.0.mac_len()
    }

    fn compute(&self, sequence_number: u32, payload: &[u8], output: &mut [u8]) {
        self.0.compute(sequence_number, payload, output)
    }

    fn verify(&self, sequence_number: u32, payload: &[u8], mac: &[u8]) -> bool {
        self.0.verify(sequence_number, payload, mac)
    }
}

#[cfg(test)]
mod tests {
    use hmac::Hmac;
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    use super::*;

    // Cross-checked against RustCrypto's own hmac/sha1/sha2, same
    // construction used by `super::super::crypto::CryptoMac` for the
    // aws-lc-rs/ring backends: HMAC(key, seqno_be || payload).
    fn rustcrypto_compute_1(key: &[u8], seqno: u32, payload: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha1> as hmac::KeyInit>::new_from_slice(key).unwrap();
        hmac::Mac::update(&mut mac, &seqno.to_be_bytes());
        hmac::Mac::update(&mut mac, payload);
        hmac::Mac::finalize(mac).into_bytes().to_vec()
    }

    fn rustcrypto_compute_256(key: &[u8], seqno: u32, payload: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).unwrap();
        hmac::Mac::update(&mut mac, &seqno.to_be_bytes());
        hmac::Mac::update(&mut mac, payload);
        hmac::Mac::finalize(mac).into_bytes().to_vec()
    }

    fn rustcrypto_compute_512(key: &[u8], seqno: u32, payload: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha512> as hmac::KeyInit>::new_from_slice(key).unwrap();
        hmac::Mac::update(&mut mac, &seqno.to_be_bytes());
        hmac::Mac::update(&mut mac, payload);
        hmac::Mac::finalize(mac).into_bytes().to_vec()
    }

    #[test]
    fn hmac_sha1_matches_rustcrypto() {
        let key = [0x3c; 20];
        let algo = OsslHmacAlgorithm {
            digest: HmacDigest::Sha1,
            key_len: 20,
        };
        let mac = algo.make_mac(&key);
        let mut out = vec![0u8; mac.mac_len()];
        mac.compute(99, b"legacy mac payload", &mut out);
        assert_eq!(out, rustcrypto_compute_1(&key, 99, b"legacy mac payload"));
    }

    #[test]
    fn hmac_sha256_matches_rustcrypto() {
        let key = [0x5a; 32];
        let algo = OsslHmacAlgorithm {
            digest: HmacDigest::Sha256,
            key_len: 32,
        };
        let mac = algo.make_mac(&key);
        let mut out = vec![0u8; mac.mac_len()];
        mac.compute(42, b"ssh packet payload", &mut out);
        assert_eq!(out, rustcrypto_compute_256(&key, 42, b"ssh packet payload"));
        assert!(mac.verify(42, b"ssh packet payload", &out));
        assert!(!mac.verify(43, b"ssh packet payload", &out));
    }

    #[test]
    fn hmac_sha512_matches_rustcrypto() {
        let key = [0xa5; 64];
        let algo = OsslHmacAlgorithm {
            digest: HmacDigest::Sha512,
            key_len: 64,
        };
        let mac = algo.make_mac(&key);
        let mut out = vec![0u8; mac.mac_len()];
        mac.compute(7, b"another payload", &mut out);
        assert_eq!(out, rustcrypto_compute_512(&key, 7, b"another payload"));
    }

    #[test]
    fn etm_variant_computes_the_same_tag() {
        let key = [0x11; 32];
        let plain = OsslHmacAlgorithm {
            digest: HmacDigest::Sha256,
            key_len: 32,
        }
        .make_mac(&key);
        let etm = OsslEtmHmacAlgorithm {
            digest: HmacDigest::Sha256,
            key_len: 32,
        }
        .make_mac(&key);
        let mut plain_out = vec![0u8; plain.mac_len()];
        let mut etm_out = vec![0u8; etm.mac_len()];
        plain.compute(1, b"data", &mut plain_out);
        etm.compute(1, b"data", &mut etm_out);
        assert_eq!(plain_out, etm_out);
        assert!(etm.is_etm());
        assert!(!plain.is_etm());
    }
}
