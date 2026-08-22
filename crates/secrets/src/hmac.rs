//! RFC 2104 HMAC, specialized to SHA-1 — the only hash this crate owns.
//! Zero dependencies, built on [`crate::sha1::sha1`].
//!
//! Test suite: the standard HMAC-SHA1 vectors (RFC 2104 §2's construction,
//! test data as published in RFC 2202 §3, which is where the numeric
//! vectors for RFC 2104's algorithm actually live).

use crate::sha1::{sha1, BLOCK_LEN, DIGEST_LEN};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// RFC 2104 §2 HMAC-SHA1(`key`, `message`).
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; DIGEST_LEN] {
    // Keys longer than the block size are hashed down first (RFC 2104
    // §2); shorter keys are zero-padded out to the block size.
    let mut key_block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let hashed = sha1(key);
        key_block[..DIGEST_LEN].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK_LEN + message.len());
    inner.extend(key_block.iter().map(|b| b ^ IPAD));
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(BLOCK_LEN + DIGEST_LEN);
    outer.extend(key_block.iter().map(|b| b ^ OPAD));
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2202 §3 Test Case 1 (key <= block size, no hashing-down needed).
    #[test]
    fn test_case_1_key_shorter_than_block_size() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha1(&key, b"Hi There");
        assert_eq!(hex(&mac), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    // RFC 2202 §3 Test Case 2.
    #[test]
    fn test_case_2_ascii_key_and_data() {
        let mac = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex(&mac), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    // RFC 2202 §3 Test Case 3 (data longer than one block, exercises
    // multi-block SHA-1 inside the HMAC construction).
    #[test]
    fn test_case_3_data_longer_than_one_block() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        let mac = hmac_sha1(&key, &data);
        assert_eq!(hex(&mac), "125d7342b9ac11cd91a39af48aa17b4f63f175d3");
    }

    // RFC 2202 §3 Test Case 6 (key LONGER than the block size — the one
    // vector that exercises the hash-the-key-down branch).
    #[test]
    fn test_case_6_key_longer_than_block_size() {
        let key = [0xaau8; 80];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let mac = hmac_sha1(&key, data);
        assert_eq!(hex(&mac), "aa4ae5e15272d00e95705637ce8a3b55ed402112");
    }

    // Key-exactly-64-bytes boundary (P-V1 review nit): `key.len() >
    // BLOCK_LEN` is a strict `>`, so a 64-byte key takes the zero-pad
    // (else) branch, not the hash-the-key-down branch — this is the one
    // length where that boundary condition is actually exercised.
    // Independently verified against `openssl dgst -mac HMAC`.
    #[test]
    fn key_exactly_block_size_takes_the_zero_pad_branch() {
        let key = [0xccu8; BLOCK_LEN];
        assert_eq!(key.len(), BLOCK_LEN);
        let mac = hmac_sha1(&key, b"boundary key test message");
        assert_eq!(hex(&mac), "0301feda67b20f871fae1d5bbfef8f929ca5fdcf");
    }
}
