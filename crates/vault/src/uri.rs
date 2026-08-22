//! `otpauth://` enrollment URI construction — pure string building for
//! V3's `vault enroll`. Follows the de-facto Google Authenticator
//! key-uri format (no RFC of its own; the format every TOTP app
//! interoperates on): `otpauth://totp/<issuer>:<label>?secret=<base32>&
//! issuer=<issuer>&algorithm=SHA1&digits=6&period=30`.

/// Percent-encode per RFC 3986's unreserved set (`A-Z a-z 0-9 - _ . ~`);
/// everything else becomes `%XX`. This crate has no `url` dependency —
/// `label`/`issuer` are short trusted-ish identifiers, not general URLs,
/// so a minimal encoder is the whole job.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Build an `otpauth://totp/...` enrollment URI. `label` identifies the
/// account/consumer shown in the authenticator app; `issuer` is the
/// vault's identity (e.g. `aoide-vault@<host>`); `secret` is the raw
/// TOTP key (base32-encoded here — callers never pre-encode it). Fixed
/// at this crate's RFC 6238 parameters: SHA1, 6 digits,
/// [`crate::totp::STEP_SECONDS`].
pub fn totp_uri(label: &str, issuer: &str, secret: &[u8]) -> String {
    let secret_b32 = crate::base32::encode(secret);
    let enc_issuer = percent_encode(issuer);
    let enc_label = percent_encode(label);
    format!(
        "otpauth://totp/{enc_issuer}:{enc_label}?secret={secret_b32}&issuer={enc_issuer}&algorithm=SHA1&digits=6&period={period}",
        period = crate::totp::STEP_SECONDS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_expected_uri_shape() {
        let secret = b"12345678901234567890";
        let uri = totp_uri("m", "aoide-vault", secret);
        let expected_b32 = crate::base32::encode(secret);
        assert_eq!(
            uri,
            format!(
                "otpauth://totp/aoide-vault:m?secret={expected_b32}&issuer=aoide-vault&algorithm=SHA1&digits=6&period=30"
            )
        );
    }

    #[test]
    fn percent_encodes_reserved_characters_in_label_and_issuer() {
        let uri = totp_uri("m consumer", "aoide vault: sakaki", b"x");
        assert!(uri.contains("m%20consumer"));
        assert!(uri.contains("aoide%20vault%3A%20sakaki"));
        // secret and query keys stay unescaped.
        assert!(uri.contains("secret="));
        assert!(uri.contains("&algorithm=SHA1&digits=6&period=30"));
    }

    #[test]
    fn secret_round_trips_through_base32_in_the_uri() {
        let secret = b"a-real-looking-secret!!";
        let uri = totp_uri("m", "aoide-vault", secret);
        let encoded = crate::base32::encode(secret);
        assert!(uri.contains(&format!("secret={encoded}")));
        assert_eq!(crate::base32::decode(&encoded).unwrap(), secret);
    }
}
