//! HMAC-SHA2-256/512 (and their `-etm@openssh.com` variants) via system
//! OpenSSL, for environments that require all cryptographic operations to
//! go through a FIPS-certifiable OpenSSL build. `hmac-sha1`/`hmac-sha1-etm`
//! stay RustCrypto-only: they're legacy/deprecated algorithms, and `sha1`
//! is already unavoidably present in the build via unrelated dependencies
//! (axum/tungstenite's WebSocket handshake), so there is nothing to gain
//! by porting them specifically.

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
    Sha256,
    Sha512,
}

impl HmacDigest {
    fn message_digest(self) -> MessageDigest {
        match self {
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
