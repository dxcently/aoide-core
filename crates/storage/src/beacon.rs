//! The discovery beacon wire format (P-P6, `docs/architecture/PAIRING.md`'s
//! "Discovery (advertise-but-locked)" section): the one JSON line an `a2a
//! serve` process may emit on a fixed UDP multicast group+port when
//! discovery advertising is turned on, and the validation an `aoide peer
//! discover`/`peer invite` sweep applies to every line it hears before
//! trusting a single field of it (root `AGENTS.md` house rule 4 — a beacon
//! heard off the network is untrusted data, no different from a forwarded
//! notification's text).
//!
//! **Discovery grants NOTHING** (PAIRING.md, verbatim): a beacon only ever
//! feeds `peer discover`'s printed table and `peer invite`'s URL
//! resolution — the pairing ceremony (`peer pair request`, P-P2) is the
//! only thing that ever writes `state/peers.json`. This module has no
//! dependency on `peer_store` for writing anything, and never will; it
//! reaches into it for exactly one READ (`valid_peer_name`, the same
//! nickname shape every other peer-name field on the wire already holds
//! to) so the beacon's `name` never gets a second, drifting shape check.
//!
//! **Constants pinned here, once** — `CONTRACTS.md §6`'s "Discovery beacon"
//! subsection carries the same values and must be updated in the same
//! commit as any change here: [`GROUP`]/[`PORT`] are an admin-scoped (RFC
//! 2365 site-local, `239.255.0.0/16`) IPv4 multicast group + a UDP port,
//! chosen to collide with nothing else this repo binds — grepped clean:
//! `a2a serve`'s own `TcpListener::bind` (TCP `8710`) is the only other
//! bound port anywhere in `pkgs/aoide`, a different protocol/port-space
//! entirely, and every other door in this tree (`aoided`, the secrets
//! broker) is a unix-domain socket with no port at all. `239.255.87.10:8711`
//! is a mnemonic echo of the A2A door's own `8710` (`"87.10"` spelled into
//! the group's last two octets, `8711` one past it), not an arbitrary roll.
//!
//! **Wire shape**: `{v, name, fpr, url}` (PAIRING.md, verbatim field set) —
//! protocol version, the advertiser's own instance name
//! (`aoide_server::a2a::resolve_peer_name`'s same value), its P-P1 identity
//! fingerprint ([`crate::identity::IdentityInfo::fingerprint`],
//! colon-separated, never the full public key), and the A2A door URL that
//! instance's own `a2a serve` is actually answering on. Never a credential,
//! never a full pubkey.

use serde::{Deserialize, Serialize};

/// The beacon's own `v` field. Bumped only on a wire-incompatible change —
/// [`parse_and_validate`] refuses any other value outright, the same
/// "don't silently accept a shape we don't understand" stance every other
/// validator below holds.
pub const VERSION: u32 = 1;

/// The multicast group every `a2a serve` advertiser sends to and every
/// `peer discover`/`peer invite` sweep joins — `239.255.0.0/16`, RFC 2365's
/// administratively (site-local) scoped range, so a beacon never crosses a
/// router boundary its operator didn't explicitly configure for it.
pub const GROUP: &str = "239.255.87.10";

/// The UDP port paired with [`GROUP`]. Distinct from `a2a serve`'s own TCP
/// `8710` (a different protocol/port-space entirely, so there is no real
/// collision either way) — picked one past it as a mnemonic pairing, not
/// because `8710` itself was unavailable.
pub const PORT: u16 = 8711;

/// Hard cap on one beacon LINE (raw bytes), checked BEFORE any JSON parse
/// is attempted, on BOTH ends: a sender that would exceed this refuses to
/// emit rather than truncate ([`encode`]); a listener drops and counts
/// anything over this without ever touching its content
/// ([`parse_and_validate`]) — the same "cheapest check first, on untrusted
/// bytes" discipline `aoide-server`'s own `daemon::read_capped_line`/
/// `a2a::MAX_LINE` already hold for their own line-oriented inputs. A real
/// beacon (fixed `v`, a `valid_peer_name`-shaped name, a 23-character
/// fingerprint, a URL under [`MAX_URL_LEN`]) never approaches this; it
/// exists to bound a hostile or corrupt sender, never a legitimate one.
pub const MAX_LINE_BYTES: usize = 512;

/// Cap on the `url` field specifically — generous for any real
/// `scheme://host:port/` door URL, far short of [`MAX_LINE_BYTES`] on its
/// own.
const MAX_URL_LEN: usize = 256;

/// One beacon. See the module doc for the field meanings and the
/// "grants nothing" invariant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Beacon {
    pub v: u32,
    pub name: String,
    pub fpr: String,
    pub url: String,
}

/// Build this instance's own beacon — the ONE constructor, so `v` can never
/// drift from [`VERSION`] at a call site.
pub fn build(name: &str, fpr: &str, url: &str) -> Beacon {
    Beacon {
        v: VERSION,
        name: name.to_string(),
        fpr: fpr.to_string(),
        url: url.to_string(),
    }
}

/// Serialize a beacon to its one wire line — `None` if the encoded line
/// would exceed [`MAX_LINE_BYTES`] (a defensive floor: every field a real
/// advertiser passes through [`build`] is already bounded well under this
/// in practice, so this only ever fires against a caller bug, never a
/// legitimate identity/name/url).
pub fn encode(b: &Beacon) -> Option<String> {
    let line = serde_json::to_string(b).ok()?;
    if line.len() > MAX_LINE_BYTES {
        return None;
    }
    Some(line)
}

/// Why a raw line was refused. Never rendered with the attacker's own
/// bytes inside it (house rule 4) — a caller reports the COUNT of drops,
/// never one of these variants' content, over the wire or CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    TooLarge,
    Unparseable,
    WrongVersion,
    InvalidName,
    InvalidFingerprint,
    InvalidUrl,
}

/// A colon-separated 8-byte hex fingerprint, exactly
/// [`crate::identity`]'s own `fingerprint()` render shape
/// (`aa:bb:cc:dd:ee:ff:00:11`) — 8 lowercase hex pairs joined by `:`, 23
/// characters total. Pure.
pub fn valid_fingerprint(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 8
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)))
}

/// An `http://`/`https://` URL, sane enough to dial — scheme-restricted
/// (unlike `pairing::valid_callback_url`'s any-`://` shape;
/// `aoide-server::a2a`'s own pairing-wire validators live crate-side of a
/// different door and this module deliberately does not reuse them —
/// PAIRING.md spells out "http(s) url" explicitly for the beacon, a
/// narrower shape), non-empty host, under [`MAX_URL_LEN`]. Pure.
pub fn valid_url(s: &str) -> bool {
    if s.len() > MAX_URL_LEN {
        return false;
    }
    let rest = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://"));
    match rest {
        Some(r) => !r.split('/').next().unwrap_or("").is_empty(),
        None => false,
    }
}

/// Parse and fully validate one raw line heard off the multicast socket —
/// the ONE gate every field crosses before a caller may look at it (house
/// rule 4): the size cap first (cheapest check, on raw bytes, before a
/// single byte reaches a JSON parser), then the parse itself, then `v`,
/// `name` ([`crate::peer_store::valid_peer_name`]), `fpr`
/// ([`valid_fingerprint`]), and `url` ([`valid_url`]) — in that order,
/// short-circuiting on the first failure. `peer discover`/`peer invite`
/// never display a line that fails any one of these; they only ever
/// increment a dropped count.
pub fn parse_and_validate(line: &str) -> Result<Beacon, RejectReason> {
    if line.len() > MAX_LINE_BYTES {
        return Err(RejectReason::TooLarge);
    }
    let b: Beacon = serde_json::from_str(line).map_err(|_| RejectReason::Unparseable)?;
    if b.v != VERSION {
        return Err(RejectReason::WrongVersion);
    }
    if !crate::peer_store::valid_peer_name(&b.name) {
        return Err(RejectReason::InvalidName);
    }
    if !valid_fingerprint(&b.fpr) {
        return Err(RejectReason::InvalidFingerprint);
    }
    if !valid_url(&b.url) {
        return Err(RejectReason::InvalidUrl);
    }
    Ok(b)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Beacon {
        build("yomi-strix", "aa:bb:cc:dd:ee:ff:00:11", "http://yomi-strix:8710/")
    }

    #[test]
    fn encode_then_parse_and_validate_round_trips() {
        let b = sample();
        let line = encode(&b).expect("a well-formed beacon always encodes");
        let parsed = parse_and_validate(&line).expect("a genuine encoded beacon always validates");
        assert_eq!(parsed, b);
    }

    #[test]
    fn a_bad_name_is_dropped_and_never_touches_the_other_checks() {
        let mut b = sample();
        b.name = "../evil".to_string();
        let line = serde_json::to_string(&b).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::InvalidName));
    }

    #[test]
    fn a_bad_fingerprint_is_dropped() {
        let mut b = sample();
        b.fpr = "not-a-fingerprint".to_string();
        let line = serde_json::to_string(&b).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::InvalidFingerprint));

        // Right length, wrong grouping (no colons) must also fail — the
        // shape check is structural, not just a length count.
        let mut b2 = sample();
        b2.fpr = "aabbccddeeff0011aabbcc".to_string();
        let line2 = serde_json::to_string(&b2).unwrap();
        assert_eq!(parse_and_validate(&line2), Err(RejectReason::InvalidFingerprint));
    }

    #[test]
    fn a_non_http_url_is_dropped() {
        let mut b = sample();
        b.url = "ftp://yomi-strix:8710/".to_string();
        let line = serde_json::to_string(&b).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::InvalidUrl));

        let mut b2 = sample();
        b2.url = "not a url at all".to_string();
        let line2 = serde_json::to_string(&b2).unwrap();
        assert_eq!(parse_and_validate(&line2), Err(RejectReason::InvalidUrl));

        let mut b3 = sample();
        b3.url = "http://".to_string(); // scheme present, empty host
        let line3 = serde_json::to_string(&b3).unwrap();
        assert_eq!(parse_and_validate(&line3), Err(RejectReason::InvalidUrl));
    }

    #[test]
    fn an_oversize_line_is_dropped_before_any_parse() {
        let huge = "x".repeat(MAX_LINE_BYTES + 1);
        assert_eq!(parse_and_validate(&huge), Err(RejectReason::TooLarge));

        // A beacon whose URL alone pushes the WHOLE line over the cap is
        // dropped the same way, proving the check is on the raw line, not
        // the parsed struct.
        let mut b = sample();
        b.url = format!("http://{}/", "x".repeat(MAX_LINE_BYTES));
        let line = serde_json::to_string(&b).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::TooLarge));
    }

    #[test]
    fn an_unparseable_line_is_dropped() {
        assert_eq!(parse_and_validate("not json"), Err(RejectReason::Unparseable));
        assert_eq!(parse_and_validate("{\"v\":1}"), Err(RejectReason::Unparseable));
    }

    #[test]
    fn a_future_protocol_version_is_dropped() {
        let mut b = sample();
        b.v = 2;
        let line = serde_json::to_string(&b).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::WrongVersion));
    }

    #[test]
    fn encode_refuses_a_beacon_whose_line_would_exceed_the_cap() {
        let mut b = sample();
        b.url = format!("http://{}/", "x".repeat(MAX_LINE_BYTES));
        assert_eq!(encode(&b), None);
    }

    #[test]
    fn valid_fingerprint_accepts_the_exact_render_shape_and_rejects_near_misses() {
        assert!(valid_fingerprint("aa:bb:cc:dd:ee:ff:00:11"));
        assert!(!valid_fingerprint("aa:bb:cc:dd:ee:ff:00")); // 7 groups
        assert!(!valid_fingerprint("aa:bb:cc:dd:ee:ff:00:1")); // short last group
        assert!(!valid_fingerprint("AA:bb:cc:dd:ee:ff:00:11")); // uppercase — never emitted, never accepted
        assert!(!valid_fingerprint("aabbccddeeff0011")); // no separators at all
    }

    #[test]
    fn valid_url_accepts_http_and_https_only() {
        assert!(valid_url("http://yomi-strix:8710/"));
        assert!(valid_url("https://yomi-strix:8710/"));
        assert!(!valid_url("ftp://yomi-strix:8710/"));
        assert!(!valid_url("yomi-strix:8710"));
        assert!(!valid_url(""));
    }
}
