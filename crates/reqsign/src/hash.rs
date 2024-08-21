//! Hash related utils.

use anyhow::anyhow;
use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use hmac::Hmac;
use hmac::Mac;
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha256;

/// Base64 encode
pub fn base64_encode(content: &[u8]) -> String {
    BASE64_STANDARD.encode(content)
}

// Base64 decode
pub fn base64_decode(content: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(content)
        .map_err(|e| anyhow!("base64 decode failed for {e:?}"))
}

/// SHA256 hash.
#[allow(dead_code)]
pub fn sha256(content: &[u8]) -> Vec<u8> {
    Sha256::digest(content).as_slice().to_vec()
}

/// Hex encoded SHA1 hash.
///
/// Use this function instead of `hex::encode(sha1(content))` can reduce
/// extra copy.
pub fn hex_sha1(content: &[u8]) -> String {
    hex::encode(Sha1::digest(content).as_slice())
}

/// Hex encoded SHA256 hash.
///
/// Use this function instead of `hex::encode(sha256(content))` can reduce
/// extra copy.
pub fn hex_sha256(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content).as_slice())
}

/// HMAC with SHA256 hash.
pub fn hmac_sha256(key: &[u8], content: &[u8]) -> Vec<u8> {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("invalid key length");
    h.update(content);

    h.finalize().into_bytes().to_vec()
}

/// Base64 encoded HMAC with SHA256 hash.
pub fn base64_hmac_sha256(key: &[u8], content: &[u8]) -> String {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("invalid key length");
    h.update(content);

    base64_encode(&h.finalize().into_bytes())
}

/// Hex encoded HMAC with SHA1 hash.
///
/// Use this function instead of `hex::encode(hmac_sha1(key, content))` can
/// reduce extra copy.
pub fn hex_hmac_sha1(key: &[u8], content: &[u8]) -> String {
    let mut h = Hmac::<Sha1>::new_from_slice(key).expect("invalid key length");
    h.update(content);

    hex::encode(h.finalize().into_bytes())
}

/// Hex encoded HMAC with SHA256 hash.
///
/// Use this function instead of `hex::encode(hmac_sha256(key, content))` can
/// reduce extra copy.
pub fn hex_hmac_sha256(key: &[u8], content: &[u8]) -> String {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("invalid key length");
    h.update(content);

    hex::encode(h.finalize().into_bytes())
}

/// Base64 encoded HMAC with SHA1 hash.
pub fn base64_hmac_sha1(key: &[u8], content: &[u8]) -> String {
    let mut h = Hmac::<Sha1>::new_from_slice(key).expect("invalid key length");
    h.update(content);

    base64_encode(&h.finalize().into_bytes())
}
