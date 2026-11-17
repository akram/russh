// Copyright 2016 Pierre-Étienne Meunier
//
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

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use std::convert::TryInto;

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::{
    aead::{
        Aad, Algorithm, BoundKey, NONCE_LEN, Nonce as AeadNonce, NonceSequence,
        OpeningKey as AeadOpeningKey, SealingKey as AeadSealingKey, UnboundKey,
    },
    error::Unspecified,
};
#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
use openssl::symm::{Cipher as OsslCipher, decrypt_aead, encrypt_aead};
use rand_core::Rng;
#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
use ring::{
    aead::{
        Aad, Algorithm, BoundKey, NONCE_LEN, Nonce as AeadNonce, NonceSequence,
        OpeningKey as AeadOpeningKey, SealingKey as AeadSealingKey, UnboundKey,
    },
    error::Unspecified,
};

use super::super::Error;
use crate::keys::key::safe_rng;
use crate::mac::MacAlgorithm;

/// Padding needed so `PADDING_LENGTH_LEN + payload.len() + padding_length` is
/// a multiple of the 16-byte GCM block size, same for either backend.
fn gcm_padding_length(payload: &[u8]) -> usize {
    let block_size = 16;
    let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
    let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
        super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
    } else {
        block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
    };
    if padding_len < super::PACKET_LENGTH_LEN {
        padding_len + block_size
    } else {
        padding_len
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
pub struct GcmCipher(pub(crate) &'static Algorithm);

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
impl super::Cipher for GcmCipher {
    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn nonce_len(&self) -> usize {
        self.0.nonce_len()
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OpeningKey(AeadOpeningKey::new(
            UnboundKey::new(self.0, k).unwrap(),
            Nonce(n.try_into().unwrap()),
        )))
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(SealingKey(AeadSealingKey::new(
            UnboundKey::new(self.0, k).unwrap(),
            Nonce(n.try_into().unwrap()),
        )))
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
pub struct OpeningKey<N: NonceSequence>(AeadOpeningKey<N>);

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
pub struct SealingKey<N: NonceSequence>(AeadSealingKey<N>);

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
struct Nonce([u8; NONCE_LEN]);

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
impl NonceSequence for Nonce {
    fn advance(&mut self) -> Result<AeadNonce, Unspecified> {
        let mut previous_nonce = [0u8; NONCE_LEN];
        #[allow(clippy::indexing_slicing)] // length checked
        previous_nonce.clone_from_slice(&self.0[..]);
        let mut carry = 1;
        #[allow(clippy::indexing_slicing)] // length checked
        for i in (0..NONCE_LEN).rev() {
            let n = self.0[i] as u16 + carry;
            self.0[i] = n as u8;
            carry = n >> 8;
        }
        Ok(AeadNonce::assume_unique_for_key(previous_nonce))
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
impl<N: NonceSequence> super::OpeningKey for OpeningKey<N> {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        // Fine because of self.packet_length_to_read_for_block_length()
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().tag_len()
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        // Packet length is sent unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];

        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&ciphertext_and_tag[..super::PACKET_LENGTH_LEN]);

        let buf = self
            .0
            .open_in_place(
                Aad::from(&packet_length),
                #[allow(clippy::indexing_slicing)] // length checked
                &mut ciphertext_and_tag[super::PACKET_LENGTH_LEN..],
            )
            .map_err(|_| Error::DecryptionError)?;

        Ok(buf)
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
impl<N: NonceSequence> super::SealingKey for SealingKey<N> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        gcm_padding_length(payload)
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        self.0.algorithm().tag_len()
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        // Packet length is received unencrypted
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)] // length checked
        packet_length.clone_from_slice(&plaintext_in_ciphertext_out[..super::PACKET_LENGTH_LEN]);

        #[allow(clippy::unwrap_used)]
        let tag_out = self
            .0
            .seal_in_place_separate_tag(
                Aad::from(&packet_length),
                #[allow(clippy::indexing_slicing)]
                &mut plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..],
            )
            .unwrap();

        tag.clone_from_slice(tag_out.as_ref());
    }
}

// AES-GCM via system OpenSSL, as an alternative to ring/aws-lc-rs for
// environments that require all cryptographic operations to go through a
// FIPS-certifiable OpenSSL build. Only active when neither `aws-lc-rs` nor
// `ring` is enabled (see the feature's doc comment in Cargo.toml).
//
// `openssl::symm::{encrypt_aead, decrypt_aead}` work on whole buffers with
// a separate tag, same shape as the `seal`/`open` trait methods, so unlike
// the ring/aws-lc-rs path above there's no need for a `NonceSequence`-style
// abstraction; the 96-bit counter nonce is just a plain field, incremented
// the same way `Nonce::advance` above does it.
#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
pub struct OpenSslGcmCipher(pub(crate) usize); // key length in bytes: 16 or 32

#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
impl super::Cipher for OpenSslGcmCipher {
    fn key_len(&self) -> usize {
        self.0
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OsslOpeningKey {
            cipher: ossl_cipher_for_key_len(self.0),
            key: k.to_vec(),
            nonce: n.try_into().unwrap(),
        })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        #[allow(clippy::unwrap_used)]
        Box::new(OsslSealingKey {
            cipher: ossl_cipher_for_key_len(self.0),
            key: k.to_vec(),
            nonce: n.try_into().unwrap(),
        })
    }
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
fn ossl_cipher_for_key_len(key_len: usize) -> OsslCipher {
    if key_len == 32 {
        OsslCipher::aes_256_gcm()
    } else {
        OsslCipher::aes_128_gcm()
    }
}

/// Same 96-bit big-endian counter `Nonce::advance` above uses; returns the
/// pre-increment value (the one to actually use for this operation).
#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
fn advance_nonce(nonce: &mut [u8; 12]) -> [u8; 12] {
    let previous = *nonce;
    let mut carry = 1u16;
    #[allow(clippy::indexing_slicing)]
    for i in (0..nonce.len()).rev() {
        let n = nonce[i] as u16 + carry;
        nonce[i] = n as u8;
        carry = n >> 8;
    }
    previous
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
const OSSL_GCM_TAG_LEN: usize = 16;

#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
pub struct OsslOpeningKey {
    cipher: OsslCipher,
    key: Vec<u8>,
    nonce: [u8; 12],
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
impl super::OpeningKey for OsslOpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        OSSL_GCM_TAG_LEN
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let tag_len = self.tag_len();
        let total = ciphertext_and_tag.len();
        if total < super::PACKET_LENGTH_LEN + tag_len {
            return Err(Error::DecryptionError);
        }

        // Packet length is sent unencrypted, and used as AAD.
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)]
        packet_length.clone_from_slice(&ciphertext_and_tag[..super::PACKET_LENGTH_LEN]);

        let ciphertext_end = total - tag_len;
        let nonce = advance_nonce(&mut self.nonce);

        #[allow(clippy::indexing_slicing)]
        let plaintext = decrypt_aead(
            self.cipher,
            &self.key,
            Some(&nonce),
            &packet_length,
            &ciphertext_and_tag[super::PACKET_LENGTH_LEN..ciphertext_end],
            &ciphertext_and_tag[ciphertext_end..],
        )
        .map_err(|_| Error::DecryptionError)?;

        #[allow(clippy::indexing_slicing)]
        ciphertext_and_tag[super::PACKET_LENGTH_LEN..super::PACKET_LENGTH_LEN + plaintext.len()]
            .copy_from_slice(&plaintext);

        #[allow(clippy::indexing_slicing)]
        Ok(&ciphertext_and_tag[super::PACKET_LENGTH_LEN..super::PACKET_LENGTH_LEN + plaintext.len()])
    }
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
pub struct OsslSealingKey {
    cipher: OsslCipher,
    key: Vec<u8>,
    nonce: [u8; 12],
}

#[cfg(all(feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
impl super::SealingKey for OsslSealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        gcm_padding_length(payload)
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        OSSL_GCM_TAG_LEN
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        // Packet length is received unencrypted, and used as AAD.
        let mut packet_length = [0; super::PACKET_LENGTH_LEN];
        #[allow(clippy::indexing_slicing)]
        packet_length.clone_from_slice(&plaintext_in_ciphertext_out[..super::PACKET_LENGTH_LEN]);

        let nonce = advance_nonce(&mut self.nonce);
        let mut tag_buf = [0u8; OSSL_GCM_TAG_LEN];

        #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
        let ciphertext = encrypt_aead(
            self.cipher,
            &self.key,
            Some(&nonce),
            &packet_length,
            &plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..],
            &mut tag_buf,
        )
        .unwrap();

        #[allow(clippy::indexing_slicing)]
        plaintext_in_ciphertext_out[super::PACKET_LENGTH_LEN..].copy_from_slice(&ciphertext);
        tag.copy_from_slice(&tag_buf);
    }
}

#[cfg(all(test, feature = "openssl", not(feature = "aws-lc-rs"), not(feature = "ring")))]
mod tests {
    use super::OpenSslGcmCipher;
    use crate::cipher::Cipher;
    use crate::mac::_NONE;

    fn roundtrip(key_len: usize) {
        let cipher = OpenSslGcmCipher(key_len);
        let key = vec![0x42; key_len];
        let nonce = [0x24; 12];

        let mut sealing_key = cipher.make_sealing_key(&key, &nonce, &[], &_NONE);
        let mut opening_key = cipher.make_opening_key(&key, &nonce, &[], &_NONE);

        let payload = b"hello, fips world";
        let packet_length: u32 = (1 + payload.len()) as u32; // padding_length byte + payload
        let mut buf = packet_length.to_be_bytes().to_vec();
        buf.push(0); // padding_length (none, for this test)
        buf.extend_from_slice(payload);
        let plaintext_region = buf[4..].to_vec();

        let mut tag = vec![0u8; sealing_key.tag_len()];
        sealing_key.seal(0, &mut buf, &mut tag);
        buf.extend_from_slice(&tag);

        // The ciphertext must actually differ from the plaintext (sanity
        // check that this didn't silently no-op).
        assert_ne!(&buf[4..4 + plaintext_region.len()], plaintext_region.as_slice());

        let opened = opening_key.open(0, &mut buf).expect("decryption should succeed");
        assert_eq!(&opened[1..], payload); // skip the padding_length byte
    }

    #[test]
    fn aes_128_gcm_openssl_roundtrip() {
        roundtrip(16);
    }

    #[test]
    fn aes_256_gcm_openssl_roundtrip() {
        roundtrip(32);
    }

    #[test]
    fn aes_128_gcm_openssl_rejects_tampered_tag() {
        let cipher = OpenSslGcmCipher(16);
        let key = vec![0x11; 16];
        let nonce = [0x22; 12];
        let mut sealing_key = cipher.make_sealing_key(&key, &nonce, &[], &_NONE);
        let mut opening_key = cipher.make_opening_key(&key, &nonce, &[], &_NONE);

        let mut buf = 5u32.to_be_bytes().to_vec();
        buf.push(0);
        buf.extend_from_slice(b"hi!!");
        let mut tag = vec![0u8; sealing_key.tag_len()];
        sealing_key.seal(0, &mut buf, &mut tag);
        buf.extend_from_slice(&tag);

        *buf.last_mut().expect("tag byte") ^= 0xff;
        assert!(opening_key.open(0, &mut buf).is_err());
    }
}
