//! RFC 4648 §6 Base32 — hand-rolled, zero dependencies. Encodes a raw TOTP
//! secret for display/URI ([`crate::uri::totp_uri`]) and decodes an
//! enrolled secret back to bytes.
//!
//! No-padding tolerance BOTH ways: [`encode`] omits the `=` padding (the
//! de-facto authenticator-app convention — Google Authenticator and every
//! compatible app display/accept base32 secrets unpadded), [`decode`]
//! accepts input with or without it (and is case-insensitive).

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `data` as unpadded RFC 4648 base32.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    for &byte in data {
        bits = (bits << 8) | byte as u32;
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            out.push(ALPHABET[((bits >> bit_count) & 0x1f) as usize] as char);
        }
    }
    if bit_count > 0 {
        out.push(ALPHABET[((bits << (5 - bit_count)) & 0x1f) as usize] as char);
    }
    out
}

/// Decode base32 `input`, tolerating optional `=` padding and any case.
/// `None` on any byte outside the alphabet (padding aside).
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let cleaned = input.trim_end_matches('=').to_ascii_uppercase();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);
    for c in cleaned.bytes() {
        let val = ALPHABET.iter().position(|&a| a == c)? as u32;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10's exact test vectors, padding stripped (we test the
    // no-padding convention; padded acceptance is covered separately).
    const VECTORS: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "MY"),
        (b"fo", "MZXQ"),
        (b"foo", "MZXW6"),
        (b"foob", "MZXW6YQ"),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI"),
    ];

    #[test]
    fn encode_matches_rfc_4648_section_10_vectors() {
        for &(input, expected) in VECTORS {
            assert_eq!(encode(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn decode_matches_rfc_4648_section_10_vectors() {
        for &(expected, encoded) in VECTORS {
            assert_eq!(decode(encoded).unwrap(), expected, "encoded {encoded:?}");
        }
    }

    #[test]
    fn decode_tolerates_padding_and_lowercase() {
        assert_eq!(decode("MY======").unwrap(), b"f");
        assert_eq!(decode("my======").unwrap(), b"f");
        assert_eq!(decode("mzxw6ytb").unwrap(), b"fooba");
        assert_eq!(decode("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    #[test]
    fn decode_rejects_invalid_characters() {
        assert_eq!(decode("!!!!"), None);
        assert_eq!(decode("MY1"), None); // '1' is not in the alphabet
    }

    #[test]
    fn round_trips_arbitrary_bytes() {
        let secret: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&secret)).unwrap(), secret);
    }
}
