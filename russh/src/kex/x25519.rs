//! X25519 scalar/point operations (RFC 7748), shared by `curve25519.rs` and
//! the X25519 half of `hybrid_mlkem.rs`. Both backends operate on raw
//! 32-byte arrays so callers don't need to know which one is active.

#[cfg(feature = "openssl")]
pub(super) fn base_clamped(secret: &[u8; 32]) -> [u8; 32] {
    let pkey = openssl::pkey::PKey::private_key_from_raw_bytes(secret, openssl::pkey::Id::X25519)
        .expect("a 32-byte secret is always a valid X25519 private key");
    let raw = pkey
        .raw_public_key()
        .expect("an X25519 PKey always has a public component");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

#[cfg(feature = "openssl")]
pub(super) fn clamped(point: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
    use openssl::derive::Deriver;
    use openssl::pkey::{Id, PKey};

    // Some OpenSSL versions reject certain low-order/degenerate X25519
    // peer points at the EVP layer instead of returning an all-zero
    // result; callers already treat an all-zero shared secret as
    // non-contributory and reject it, so collapse either outcome to
    // that same sentinel rather than letting a derive error panic here.
    let result = (|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let our_secret = PKey::private_key_from_raw_bytes(secret, Id::X25519)?;
        let peer_public = PKey::public_key_from_raw_bytes(point, Id::X25519)?;
        let mut deriver = Deriver::new(&our_secret)?;
        deriver.set_peer(&peer_public)?;
        deriver.derive_to_vec()
    })();

    let mut out = [0u8; 32];
    if let Ok(shared) = result {
        if shared.len() == 32 {
            out.copy_from_slice(&shared);
        }
    }
    out
}

#[cfg(not(feature = "openssl"))]
pub(super) fn base_clamped(secret: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*secret).0
}

#[cfg(not(feature = "openssl"))]
pub(super) fn clamped(point: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
    curve25519_dalek::montgomery::MontgomeryPoint(*point)
        .mul_clamped(*secret)
        .0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_clamped_matches_clamped_with_known_basepoint() {
        // Smoke test: a keypair's public key, derived via `clamped` against
        // the standard X25519 basepoint (u=9), must equal `base_clamped`'s
        // output for the same secret.
        let mut basepoint = [0u8; 32];
        basepoint[0] = 9;
        let secret = [7u8; 32];
        assert_eq!(base_clamped(&secret), clamped(&basepoint, &secret));
    }

    #[test]
    fn clamped_is_symmetric() {
        let alice_secret = [11u8; 32];
        let bob_secret = [22u8; 32];
        let alice_public = base_clamped(&alice_secret);
        let bob_public = base_clamped(&bob_secret);
        assert_eq!(
            clamped(&bob_public, &alice_secret),
            clamped(&alice_public, &bob_secret)
        );
    }
}
