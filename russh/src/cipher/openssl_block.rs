// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// AES-CBC and AES-CTR via system OpenSSL, for environments that require all
// cryptographic operations to go through a FIPS-certifiable OpenSSL build.
// `aes`/`cbc`/`ctr` (RustCrypto) back these same ciphers for the
// aws-lc-rs/ring backends; this file is their OpenSSL-only equivalent, kept
// outside the `block::SshBlockCipher<C>` generic machinery (which is typed
// around the RustCrypto `cipher` crate's const-generic key/IV sizes) the
// same way `gcm.rs`'s `OpenSslGcmCipher` sits outside the aws-lc-rs/ring
// `GcmCipher` path.

use openssl::symm::{Cipher as OsslCipher, Crypter, Mode};

use super::super::Error;
use crate::keys::key::safe_rng;
use crate::mac::{Mac, MacAlgorithm};

#[allow(deprecated)]
use rand_core::Rng;

fn ossl_cipher_for_key_len(cbc: bool, key_len: usize) -> OsslCipher {
    match (cbc, key_len) {
        (true, 32) => OsslCipher::aes_256_cbc(),
        (true, 24) => OsslCipher::aes_192_cbc(),
        (true, _) => OsslCipher::aes_128_cbc(),
        (false, 32) => OsslCipher::aes_256_ctr(),
        (false, 24) => OsslCipher::aes_192_ctr(),
        (false, _) => OsslCipher::aes_128_ctr(),
    }
}

/// One-shot, no-padding block transform. `data.len()` must be a multiple of
/// 16 (guaranteed by the packet-length/padding scheme above this layer, the
/// same precondition the RustCrypto `CbcWrapper`/`CtrWrapper` block loops
/// rely on). Returns the output in place of `data`.
fn crypt_no_pad(
    cipher: OsslCipher,
    mode: Mode,
    key: &[u8],
    iv: &[u8; 16],
    data: &mut [u8],
) -> Result<(), Error> {
    let mut crypter = Crypter::new(cipher, mode, key, Some(iv)).map_err(|_| Error::DecryptionError)?;
    crypter.pad(false);
    let mut out = vec![0u8; data.len() + 16];
    let n = crypter
        .update(data, &mut out)
        .map_err(|_| Error::DecryptionError)?;
    let n2 = crypter
        .finalize(&mut out[n..])
        .map_err(|_| Error::DecryptionError)?;
    if n + n2 != data.len() {
        return Err(Error::DecryptionError);
    }
    #[allow(clippy::indexing_slicing)]
    data.copy_from_slice(&out[..n + n2]);
    Ok(())
}

// ---------------------------------------------------------------------
// CBC
// ---------------------------------------------------------------------

pub struct OsslCbcCipher(pub(crate) usize); // key length in bytes: 16, 24, or 32

impl super::Cipher for OsslCbcCipher {
    fn key_len(&self) -> usize {
        self.0
    }

    fn nonce_len(&self) -> usize {
        16
    }

    fn needs_mac(&self) -> bool {
        true
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OsslCbcOpeningKey {
            cipher: ossl_cipher_for_key_len(true, self.0),
            key: k.to_vec(),
            iv: n.try_into().unwrap(),
            mac: mac.make_mac(m),
        })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OsslCbcSealingKey {
            cipher: ossl_cipher_for_key_len(true, self.0),
            key: k.to_vec(),
            iv: n.try_into().unwrap(),
            mac: mac.make_mac(m),
        })
    }
}

/// Decrypt `data` (whole 16-byte blocks) chained from `iv`, without mutating
/// any persistent state; returns the new chaining IV (the last *ciphertext*
/// block, read before `data` is overwritten with plaintext).
fn cbc_decrypt_from(
    cipher: OsslCipher,
    key: &[u8],
    iv: &[u8; 16],
    data: &mut [u8],
) -> Result<[u8; 16], Error> {
    let next_iv: [u8; 16] = data
        .get(data.len().saturating_sub(16)..)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::DecryptionError)?;
    crypt_no_pad(cipher, Mode::Decrypt, key, iv, data)?;
    Ok(next_iv)
}

struct OsslCbcOpeningKey {
    cipher: OsslCipher,
    key: Vec<u8>,
    iv: [u8; 16],
    mac: Box<dyn Mac + Send>,
}

impl super::OpeningKey for OsslCbcOpeningKey {
    fn packet_length_to_read_for_block_length(&self) -> usize {
        16
    }

    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        if self.mac.is_etm() {
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            return encrypted_packet_length[..4].try_into().unwrap();
        }
        let mut probe = [0u8; 16];
        #[allow(clippy::indexing_slicing)]
        probe.copy_from_slice(&encrypted_packet_length[..16]);
        // Probe-only: discard the returned chaining IV, `self.iv` is untouched.
        let _ = cbc_decrypt_from(self.cipher, &self.key, &self.iv, &mut probe);
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        probe[..4].try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag.len() - self.tag_len();
        let (ciphertext_in_plaintext_out, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        if self.mac.is_etm() {
            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
            #[allow(clippy::indexing_slicing)]
            {
                self.iv = cbc_decrypt_from(
                    self.cipher,
                    &self.key,
                    &self.iv,
                    &mut ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..],
                )?;
            }
        } else {
            self.iv = cbc_decrypt_from(self.cipher, &self.key, &self.iv, ciphertext_in_plaintext_out)?;
            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
        }

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..])
    }
}

struct OsslCbcSealingKey {
    cipher: OsslCipher,
    key: Vec<u8>,
    iv: [u8; 16],
    mac: Box<dyn Mac + Send>,
}

impl super::SealingKey for OsslCbcSealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let pll = if self.mac.is_etm() {
            0
        } else {
            super::PACKET_LENGTH_LEN
        };
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + self.mac.mac_len();
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN - pll
        } else {
            block_size - ((pll + super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        if self.mac.is_etm() {
            #[allow(clippy::indexing_slicing, clippy::expect_used)]
            {
                crypt_no_pad(
                    self.cipher,
                    Mode::Encrypt,
                    &self.key,
                    &self.iv,
                    &mut plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..],
                )
                .expect("CBC encryption of block-aligned data cannot fail");
                #[allow(clippy::unwrap_used)]
                let new_iv: [u8; 16] = plaintext_in_ciphertext_out
                    [plaintext_in_ciphertext_out.len() - 16..]
                    .try_into()
                    .unwrap();
                self.iv = new_iv;
            }
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
        } else {
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
            #[allow(clippy::expect_used)]
            crypt_no_pad(
                self.cipher,
                Mode::Encrypt,
                &self.key,
                &self.iv,
                plaintext_in_ciphertext_out,
            )
            .expect("CBC encryption of block-aligned data cannot fail");
            #[allow(clippy::unwrap_used)]
            let new_iv: [u8; 16] = plaintext_in_ciphertext_out
                [plaintext_in_ciphertext_out.len() - 16..]
                .try_into()
                .unwrap();
            self.iv = new_iv;
        }
    }
}

// ---------------------------------------------------------------------
// CTR
// ---------------------------------------------------------------------

pub struct OsslCtrCipher(pub(crate) usize); // key length in bytes: 16, 24, or 32

impl super::Cipher for OsslCtrCipher {
    fn key_len(&self) -> usize {
        self.0
    }

    fn nonce_len(&self) -> usize {
        16
    }

    fn needs_mac(&self) -> bool {
        true
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OsslCtrKey {
            cipher: ossl_cipher_for_key_len(false, self.0),
            key: k.to_vec(),
            initial_iv: n.try_into().unwrap(),
            pos: 0,
            mac: mac.make_mac(m),
        })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        m: &[u8],
        mac: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OsslCtrKey {
            cipher: ossl_cipher_for_key_len(false, self.0),
            key: k.to_vec(),
            initial_iv: n.try_into().unwrap(),
            pos: 0,
            mac: mac.make_mac(m),
        })
    }
}

/// `initial_iv` treated as a big-endian 128-bit counter (the same convention
/// `ctr::Ctr128BE` uses), advanced by `pos / 16` whole-block increments.
fn ctr_at_pos(initial_iv: &[u8; 16], pos: u64) -> [u8; 16] {
    let base = u128::from_be_bytes(*initial_iv);
    let advanced = base.wrapping_add((pos / 16) as u128);
    advanced.to_be_bytes()
}

/// CTR is its own inverse (XOR with keystream), so the same function serves
/// both `open` and `seal`. Pure function of `(initial_iv, pos)`: used both
/// for the real, state-advancing calls and for the stateless packet-length
/// probe.
fn ctr_apply_at(
    cipher: OsslCipher,
    key: &[u8],
    initial_iv: &[u8; 16],
    pos: u64,
    data: &mut [u8],
) -> Result<(), Error> {
    let iv = ctr_at_pos(initial_iv, pos);
    crypt_no_pad(cipher, Mode::Encrypt, key, &iv, data)
}

struct OsslCtrKey {
    cipher: OsslCipher,
    key: Vec<u8>,
    initial_iv: [u8; 16],
    pos: u64,
    mac: Box<dyn Mac + Send>,
}

impl super::OpeningKey for OsslCtrKey {
    fn packet_length_to_read_for_block_length(&self) -> usize {
        16
    }

    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        if self.mac.is_etm() {
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            return encrypted_packet_length[..4].try_into().unwrap();
        }
        let mut probe = [0u8; 16];
        #[allow(clippy::indexing_slicing)]
        probe.copy_from_slice(&encrypted_packet_length[..16]);
        let _ = ctr_apply_at(self.cipher, &self.key, &self.initial_iv, self.pos, &mut probe);
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        probe[..4].try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag.len() - self.tag_len();
        let (ciphertext_in_plaintext_out, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        if self.mac.is_etm() {
            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
            #[allow(clippy::indexing_slicing)]
            {
                let region = &mut ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..];
                ctr_apply_at(self.cipher, &self.key, &self.initial_iv, self.pos, region)?;
                self.pos += region.len() as u64;
            }
        } else {
            ctr_apply_at(
                self.cipher,
                &self.key,
                &self.initial_iv,
                self.pos,
                ciphertext_in_plaintext_out,
            )?;
            self.pos += ciphertext_in_plaintext_out.len() as u64;
            if !self
                .mac
                .verify(sequence_number, ciphertext_in_plaintext_out, tag)
            {
                return Err(Error::PacketAuth);
            }
        }

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_in_plaintext_out[super::PACKET_LENGTH_LEN..])
    }
}

impl super::SealingKey for OsslCtrKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let pll = if self.mac.is_etm() {
            0
        } else {
            super::PACKET_LENGTH_LEN
        };
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + self.mac.mac_len();
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN - pll
        } else {
            block_size - ((pll + super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.mac.mac_len()
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        if self.mac.is_etm() {
            #[allow(clippy::indexing_slicing, clippy::expect_used)]
            {
                let region = &mut plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..];
                ctr_apply_at(self.cipher, &self.key, &self.initial_iv, self.pos, region)
                    .expect("CTR keystream application cannot fail");
                self.pos += region.len() as u64;
            }
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
        } else {
            self.mac
                .compute(sequence_number, plaintext_in_ciphertext_out, tag_out);
            #[allow(clippy::expect_used)]
            ctr_apply_at(
                self.cipher,
                &self.key,
                &self.initial_iv,
                self.pos,
                plaintext_in_ciphertext_out,
            )
            .expect("CTR keystream application cannot fail");
            self.pos += plaintext_in_ciphertext_out.len() as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OsslCbcCipher, OsslCtrCipher};
    use crate::cipher::Cipher;
    use crate::mac::_NONE;

    fn roundtrip_block_cipher(cipher: &dyn Cipher, key_len: usize) {
        let key = vec![0x42; key_len];
        let iv = [0x24; 16];

        let mut sealing_key = cipher.make_sealing_key(&key, &iv, &[], &_NONE);
        let mut opening_key = cipher.make_opening_key(&key, &iv, &[], &_NONE);

        // Two packets, to exercise IV/counter chaining across calls. Padding
        // is computed the same way `finish_packet` would (so the *total*
        // buffer, packet_length field included, lands on a block boundary),
        // not just the packet_length/padding_length/payload/padding region.
        for payload in [&b"hello, fips world"[..], &b"a second packet, different length!"[..]] {
            let padded_len = sealing_key.padding_length(payload);
            let packet_length: u32 = (1 + payload.len() + padded_len) as u32;
            let mut buf = packet_length.to_be_bytes().to_vec();
            buf.push(padded_len as u8);
            buf.extend_from_slice(payload);
            buf.extend(std::iter::repeat_n(0u8, padded_len));
            let plaintext_region = buf[4..].to_vec();

            let mut tag = vec![0u8; sealing_key.tag_len()];
            sealing_key.seal(0, &mut buf, &mut tag);
            buf.extend_from_slice(&tag);

            assert_ne!(&buf[4..4 + plaintext_region.len()], plaintext_region.as_slice());

            let opened = opening_key.open(0, &mut buf).expect("decryption should succeed");
            assert_eq!(&opened[..1 + payload.len()], &plaintext_region[..1 + payload.len()]);
        }
    }

    #[test]
    fn aes_128_cbc_openssl_roundtrip() {
        roundtrip_block_cipher(&OsslCbcCipher(16), 16);
    }

    #[test]
    fn aes_256_cbc_openssl_roundtrip() {
        roundtrip_block_cipher(&OsslCbcCipher(32), 32);
    }

    #[test]
    fn aes_128_ctr_openssl_roundtrip() {
        roundtrip_block_cipher(&OsslCtrCipher(16), 16);
    }

    #[test]
    fn aes_256_ctr_openssl_roundtrip() {
        roundtrip_block_cipher(&OsslCtrCipher(32), 32);
    }

    /// Cross-check against RustCrypto's `ctr::Ctr128BE<Aes128>`: same key,
    /// same IV, same plaintext must produce byte-identical ciphertext.
    #[test]
    fn aes_128_ctr_openssl_matches_rustcrypto() {
        use aes::Aes128;
        use cipher::{KeyIvInit, StreamCipher};
        use ctr::Ctr128BE;

        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let plaintext = [0x33u8; 48]; // 3 blocks

        let mut rc_cipher = Ctr128BE::<Aes128>::new(&key.into(), &iv.into());
        let mut rc_ciphertext = plaintext;
        rc_cipher.apply_keystream(&mut rc_ciphertext);

        let mut ossl_ciphertext = plaintext;
        super::ctr_apply_at(
            openssl::symm::Cipher::aes_128_ctr(),
            &key,
            &iv,
            0,
            &mut ossl_ciphertext,
        )
        .expect("ctr apply");

        assert_eq!(rc_ciphertext, ossl_ciphertext);
    }

    /// Cross-check against RustCrypto's `cbc::Encryptor<Aes128>`.
    #[test]
    fn aes_128_cbc_openssl_matches_rustcrypto() {
        use aes::Aes128;
        use cipher::{Block, BlockModeEncrypt, KeyIvInit};

        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let mut plaintext = [0x33u8; 32]; // 2 blocks

        let mut rc_encryptor = cbc::Encryptor::<Aes128>::new(&key.into(), &iv.into());
        for chunk in plaintext.chunks_exact_mut(16) {
            #[allow(clippy::unwrap_used, clippy::expect_used)]
            let block = <&mut Block<Aes128>>::try_from(&mut *chunk).unwrap();
            rc_encryptor.encrypt_block(block);
        }

        let mut ossl_ciphertext = [0x33u8; 32];
        super::crypt_no_pad(
            openssl::symm::Cipher::aes_128_cbc(),
            openssl::symm::Mode::Encrypt,
            &key,
            &iv,
            &mut ossl_ciphertext,
        )
        .expect("cbc encrypt");

        assert_eq!(plaintext, ossl_ciphertext);
    }
}
