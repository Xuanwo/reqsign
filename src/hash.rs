//! Hash related utils.

use hmac::Hmac;
use hmac::Mac;
use sha2::Digest;
use sha2::Sha256;

pub fn base64_encode(content: &[u8]) -> String {
    base64::encode(content)
}

pub fn base64_decode(content: &str) -> Vec<u8> {
    base64::decode(content).expect("base64 decode must success")
}

/// SHA256 hash.
#[allow(dead_code)]
pub fn sha256(content: &[u8]) -> Vec<u8> {
    Sha256::digest(content).as_slice().to_vec()
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

pub fn base64_hmac_sha256(key: &[u8], content: &[u8]) -> String {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("invalid key length");
    h.update(content);

    base64_encode(&h.finalize().into_bytes())
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
