//! RFC 6238 TOTP, layered over RFC 4226 HOTP's dynamic truncation, built
//! on this crate's hand-rolled [`crate::hmac::hmac_sha1`]. Clock-as-
//! parameter discipline (this crate's `AGENTS.md`): every function here
//! takes `unix_time` explicitly — nothing in this module reads the
//! system clock. A thin wrapper that calls `SystemTime::now()` and hands
//! the result in belongs to V2 (the broker), not here.
//!
//! RFC 6238's suggested defaults, used throughout: 30-second step, T0=0,
//! SHA-1. Production codes are 6 digits; [`hotp`] is generalized over the
//! digit count so RFC 6238 Appendix B's published 8-digit table can be
//! used as-is (see the `tests` module) rather than hand-deriving 6-digit
//! values nobody can check against the RFC text.

use crate::hmac::hmac_sha1;

pub const STEP_SECONDS: u64 = 30;
pub const T0: u64 = 0;
pub const DEFAULT_WINDOW: i64 = 1;
pub const DIGITS: u32 = 6;

/// RFC 6238 §4.2's timestep counter for `unix_time`.
pub fn timestep(unix_time: u64) -> u64 {
    unix_time.saturating_sub(T0) / STEP_SECONDS
}

/// RFC 4226 §5.3 dynamic truncation + `mod 10^digits` — the HOTP value
/// function, with `counter` standing in for RFC 6238's `T` (RFC 6238 §1:
/// "TOTP = HOTP(K, T)"). Public so a caller (here, the Appendix B tests)
/// can exercise 8-digit output directly against the RFC table, instead of
/// only ever seeing this crate's 6-digit production codes.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());
    let offset = (mac[19] & 0x0f) as usize;
    let bin_code = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    bin_code % 10u32.pow(digits)
}

/// The 6-digit production TOTP code for `secret` at `unix_time`.
pub fn totp6(secret: &[u8], unix_time: u64) -> u32 {
    hotp(secret, timestep(unix_time), DIGITS)
}

/// Zero-padded 6-digit display form.
pub fn format6(code: u32) -> String {
    format!("{code:06}")
}

/// Verify `code` against `secret` at `unix_time`, scanning `±window`
/// timesteps either side (RFC 6238 §5.2's acceptable-window guidance, to
/// absorb clock skew). Returns the absolute timestep that matched, so a
/// caller (the replay ledger) can record single-use against that exact
/// step rather than re-deriving it. Pure: `unix_time` is the caller's.
pub fn verify(secret: &[u8], code: u32, unix_time: u64, window: i64) -> Option<u64> {
    let center = timestep(unix_time) as i64;
    (-window..=window).find_map(|delta| {
        let step = center + delta;
        if step < 0 {
            return None;
        }
        let step = step as u64;
        (hotp(secret, step, DIGITS) == code).then_some(step)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B: secret is the ASCII digits "12345678901234567890"
    // repeated as needed for SHA1 mode (SHA1 uses the 20-byte secret
    // as-is). The table's TOTP column is 8 digits — used here AS
    // PUBLISHED via `hotp(.., 8)`, not re-derived.
    const APPENDIX_B_SECRET: &[u8] = b"12345678901234567890";

    // (unix_time, expected 8-digit code) — every SHA1 row of RFC 6238
    // Appendix B's table, verbatim.
    const APPENDIX_B_SHA1: &[(u64, u32)] = &[
        (59, 94287082),
        (1111111109, 7081804),
        (1111111111, 14050471),
        (1234567890, 89005924),
        (2000000000, 69279037),
        (20000000000, 65353130),
    ];

    #[test]
    fn appendix_b_8_digit_rows_match_the_rfc_table_as_published() {
        for &(t, expected) in APPENDIX_B_SHA1 {
            let step = timestep(t);
            assert_eq!(
                hotp(APPENDIX_B_SECRET, step, 8),
                expected,
                "unix_time {t}"
            );
        }
    }

    // This crate's production surface is 6 digits, which RFC 6238 doesn't
    // publish directly. `mod 10^6` composes with `mod 10^8` cleanly
    // (10^6 divides 10^8), so the 6-digit code is exactly the 8-digit
    // code's low 6 digits — derived from the SAME published row, not a
    // separately-trusted number.
    #[test]
    fn six_digit_codes_are_the_low_six_digits_of_the_appendix_b_rows() {
        for &(t, expected8) in APPENDIX_B_SHA1 {
            assert_eq!(totp6(APPENDIX_B_SECRET, t), expected8 % 1_000_000);
        }
    }

    #[test]
    fn format6_zero_pads() {
        assert_eq!(format6(42), "000042");
        assert_eq!(format6(89005924 % 1_000_000), "005924");
    }

    #[test]
    fn verify_accepts_within_window_and_reports_the_matched_step() {
        let secret = b"12345678901234567890";
        let code = totp6(secret, 1111111111);
        // One step early (clock skew), still within +-1.
        let matched = verify(secret, code, 1111111111 - STEP_SECONDS, DEFAULT_WINDOW);
        assert_eq!(matched, Some(timestep(1111111111)));
    }

    #[test]
    fn verify_rejects_outside_window() {
        let secret = b"12345678901234567890";
        let code = totp6(secret, 1111111111);
        let far = 1111111111 + 5 * STEP_SECONDS;
        assert_eq!(verify(secret, code, far, DEFAULT_WINDOW), None);
    }

    #[test]
    fn verify_rejects_wrong_code() {
        let secret = b"12345678901234567890";
        assert_eq!(verify(secret, 0, 1111111111, DEFAULT_WINDOW), None);
    }

    // T=0 boundary (P-V1 review nit): `unix_time = 0` puts `center` at
    // timestep 0, and a `±1` window scan reaches `step = -1` before
    // `step = 0`/`step = 1`. `verify` must not underflow computing that
    // negative step (it works in `i64`, guarding `step < 0` before ever
    // casting back to `u64`) — the T-1 side has nothing to match, T=0
    // and T+1 are both reachable and correctly identified.
    #[test]
    fn verify_at_the_unix_epoch_does_not_underflow_and_checks_t0_and_t1() {
        let secret = b"12345678901234567890";

        let code_t0 = totp6(secret, 0);
        assert_eq!(verify(secret, code_t0, 0, DEFAULT_WINDOW), Some(0));

        let code_t1 = totp6(secret, STEP_SECONDS);
        assert_eq!(verify(secret, code_t1, 0, DEFAULT_WINDOW), Some(1));

        // No timestep -1 exists to match against — confirm a code that
        // is neither T0's nor T1's is rejected rather than panicking.
        let bogus = (code_t0 + 1) % 1_000_000;
        if bogus != code_t1 {
            assert_eq!(verify(secret, bogus, 0, DEFAULT_WINDOW), None);
        }
    }
}
