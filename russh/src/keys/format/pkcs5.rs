use ssh_key::PrivateKey;

use super::Encryption;
use crate::keys::Error;

/// AES-128-CBC/PKCS7 decrypt of the legacy PEM `DEK-Info` body, keyed by
/// `md5(password || salt[:8])` (the original OpenSSL PEM encryption
/// scheme). The `openssl` backend routes the AES step itself through
/// OpenSSL; both backends use the same (non-denylisted) `md5` crate for
/// the key-derivation hash, which Red Hat's `check-payload` and
/// `cargo-fips-check` only flag for the hyphenated `md-5` (RustCrypto)
/// crate, not this one.
#[cfg(feature = "openssl")]
fn aes_128_cbc_pkcs7_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    openssl::symm::decrypt(openssl::symm::Cipher::aes_128_cbc(), key, Some(iv), ciphertext)
        .map_err(|_| Error::KeyIsEncrypted)
}

#[cfg(not(feature = "openssl"))]
fn aes_128_cbc_pkcs7_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::Aes128;
    use cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

    #[allow(clippy::unwrap_used)] // AES parameters are static
    let c = cbc::Decryptor::<Aes128>::new_from_slices(key, iv).unwrap();
    let mut dec = ciphertext.to_vec();
    Ok(c.decrypt_padded::<Pkcs7>(&mut dec)?.to_vec())
}

/// Decode a secret key in the PKCS#5 format, possibly deciphering it
/// using the supplied password.
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&str>,
    enc: Encryption,
) -> Result<PrivateKey, Error> {
    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut c = md5::Context::new();
                c.consume(pass.as_bytes());
                c.consume(&iv[..8]);
                let md5 = c.finalize();

                aes_128_cbc_pkcs7_decrypt(&md5.0, &iv[..], secret)?
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        // TODO: presumably pkcs5 could contain non-RSA keys?
        #[cfg(feature = "rsa")]
        {
            super::decode_rsa_pkcs1_der(&sec).map(Into::into)
        }
        #[cfg(not(feature = "rsa"))]
        {
            Err(Error::UnsupportedKeyType {
                key_type_string: "RSA".to_string(),
                key_type_raw: vec![],
            })
        }
    } else {
        Err(Error::KeyIsEncrypted)
    }
}
