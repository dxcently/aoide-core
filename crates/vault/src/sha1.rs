//! RFC 3174 / FIPS 180-1 SHA-1 — hand-rolled, zero dependencies (plan
//! mandate for the vault TOTP stack: no `sha1` crate anywhere in this
//! tree). Only consumer is [`crate::hmac::hmac_sha1`]; this module has no
//! reason to exist outside that role, and stops at correctness — no
//! streaming/incremental API.
//!
//! Test suite: RFC 3174 §7.3's three reference vectors, verbatim.

pub const BLOCK_LEN: usize = 64;
pub const DIGEST_LEN: usize = 20;

const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// RFC 3174 SHA-1 over `input`, returning the 20-byte digest.
pub fn sha1(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = H0;

    // RFC 3174 §4: append 0x80, then zero bytes, until the length is
    // 56 mod 64, then the original bit-length as a big-endian u64.
    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % BLOCK_LEN != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(BLOCK_LEN) {
        // RFC 3174 §6.1 step (a)/(b): 16 words from the block, extended
        // to 80 via the XOR-rotate recurrence.
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // RFC 3174 §6.1 step (c)-(e): the 80-round compression, four
        // 20-round stages with their own f/K per §5.
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; DIGEST_LEN];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 3174 §7.3 TEST1.
    #[test]
    fn abc_matches_the_rfc_3174_reference_digest() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    // RFC 3174 §7.3 TEST2.
    #[test]
    fn the_two_block_message_matches_the_rfc_3174_reference_digest() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hex(&sha1(msg)),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    // RFC 3174 §7.3 TEST3: one million repetitions of "a" — the long
    // vector, included because the plan names "RFC vectors" as the
    // contract without carving out an exception for the slow one; a
    // single SHA-1 pass over 1MB is not slow in practice.
    #[test]
    fn one_million_repetitions_of_a_matches_the_rfc_3174_reference_digest() {
        let msg = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha1(&msg)),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn empty_input_matches_the_well_known_digest() {
        assert_eq!(
            hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }
}
