//! The discovery advertisement wire format and the advertise switch (P-P6
//! + task #120, `docs/architecture/PAIRING.md`'s "Discovery
//! (advertise-but-locked)" section): the one JSON line an `a2a serve`
//! process may emit by UDP broadcast when discovery advertising is turned
//! on (`aoide peer advertise on`), and the validation an `aoide peer
//! discover`/`peer invite` sweep applies to every line it hears before
//! trusting a single field of it (root `AGENTS.md` house rule 4 — an
//! advertisement heard off the network is untrusted data, no different
//! from a forwarded notification's text).
//!
//! **Discovery grants NOTHING** (PAIRING.md, verbatim): an advertisement
//! only ever feeds `peer discover`'s printed table and `pair`'s
//! hostname-arm target resolution — the pairing ceremony (`pair`, P-P2) is
//! the only thing that ever writes `state/peers.json`. This module has no
//! dependency on `peer_store` for writing anything, and never will; it
//! reaches into it for exactly one READ (`valid_peer_name`, the same
//! nickname shape every other peer-name field on the wire already holds
//! to) so the advertisement's `name` never gets a second, drifting shape
//! check.
//!
//! **Discovery is rendezvous, not authentication.** The wire carries this
//! instance's name plus its ssh hop info (`host`/`user`, the makings of a
//! `--via ssh://user@host` transport marker) and NOTHING else — never a
//! door URL on a routable address (doors are loopback-bound; ssh is the
//! only cross-box transport), never an identity fingerprint or public key
//! (a key on a discovery wire invites treating discovery as trust;
//! pairing's mutual SAS confirmation stays the one trust gate).
//!
//! **Constants pinned here, once** — `CONTRACTS.md §6`'s "Discovery
//! advertisement" subsection carries the same values and must be updated
//! in the same commit as any change here: [`BROADCAST_ADDR`]/[`PORT`] are
//! the IPv4 limited-broadcast address and a UDP port chosen to collide
//! with nothing else this repo binds — `a2a serve`'s own
//! `TcpListener::bind` (TCP `8710`) is the only other bound port anywhere
//! in `pkgs/aoide`, a different protocol/port-space entirely, and every
//! other door in this tree (`aoided`, the secrets broker) is a
//! unix-domain socket with no port at all. `8711` is a mnemonic echo of
//! the A2A door's own `8710`, one past it. Broadcast (task #120's #106
//! fix) replaced the original multicast group outright: the User's router
//! eats cross-box multicast (verified live 2026-08-27, each box heard
//! only itself), a LAN this size needs none of multicast's efficiency,
//! and a plain `0.0.0.0` bind on the listener accepts broadcast and
//! unicast datagrams with no group join, no interface pinning, and no
//! multicast-capability probing at all.

use serde::{Deserialize, Serialize};

/// The advertisement's own `v` field. Bumped only on a wire-incompatible
/// change — [`parse_and_validate`] refuses any other value outright, the
/// same "don't silently accept a shape we don't understand" stance every
/// other validator below holds. `2` dropped v1's `fpr`/`url` fields for
/// `host`/`user` (task #120: rendezvous, not authentication) — a v1 line
/// heard from a not-yet-rebuilt advertiser is dropped and counted, never
/// half-parsed.
pub const VERSION: u32 = 2;

/// The IPv4 limited-broadcast address every advertiser sends to —
/// link-local by definition, so an advertisement never crosses a router.
pub const BROADCAST_ADDR: &str = "255.255.255.255";

/// The UDP port paired with [`BROADCAST_ADDR`]. Distinct from `a2a
/// serve`'s own TCP `8710` (a different protocol/port-space entirely, so
/// there is no real collision either way) — picked one past it as a
/// mnemonic pairing, not because `8710` itself was unavailable.
pub const PORT: u16 = 8711;

/// Hard cap on one advertisement LINE (raw bytes), checked BEFORE any JSON
/// parse is attempted, on BOTH ends: a sender that would exceed this
/// refuses to emit rather than truncate ([`encode`]); a listener drops and
/// counts anything over this without ever touching its content
/// ([`parse_and_validate`]) — the same "cheapest check first, on untrusted
/// bytes" discipline `aoide-server`'s own `daemon::read_capped_line`/
/// `a2a::MAX_LINE` already hold for their own line-oriented inputs. A real
/// advertisement (fixed `v`, a `valid_peer_name`-shaped name, a
/// [`valid_host`]-shaped host, a [`valid_user`]-shaped user) never
/// approaches this; it exists to bound a hostile or corrupt sender, never
/// a legitimate one.
pub const MAX_LINE_BYTES: usize = 512;

/// Cap on the `host` field — RFC 1035's own limit on a full domain name.
const MAX_HOST_LEN: usize = 253;

/// Cap on the `user` field — `useradd`'s own login-name limit.
const MAX_USER_LEN: usize = 32;

/// One advertisement. See the module doc for the field meanings and the
/// "grants nothing" / "rendezvous, not authentication" invariants: `name`
/// is the advertiser's own instance name, `host`/`user` its claimed ssh
/// hop (`--via ssh://user@host`). The host a consumer should PREFER is the
/// packet's observed source address (`aoide-client::discover::Heard::
/// src_addr`) — `host` here is a claim, kept for display and for the
/// operator who wants a name instead of a DHCP lease.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advertisement {
    pub v: u32,
    pub name: String,
    pub host: String,
    pub user: String,
}

/// Build this instance's own advertisement — the ONE constructor, so `v`
/// can never drift from [`VERSION`] at a call site.
pub fn build(name: &str, host: &str, user: &str) -> Advertisement {
    Advertisement {
        v: VERSION,
        name: name.to_string(),
        host: host.to_string(),
        user: user.to_string(),
    }
}

/// Serialize an advertisement to its one wire line — `None` if the encoded
/// line would exceed [`MAX_LINE_BYTES`] (a defensive floor: every field a
/// real advertiser passes through [`build`] is already bounded well under
/// this in practice, so this only ever fires against a caller bug, never a
/// legitimate name/host/user).
pub fn encode(a: &Advertisement) -> Option<String> {
    let line = serde_json::to_string(a).ok()?;
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
    InvalidHost,
    InvalidUser,
}

/// A hostname or dotted-quad shape sane enough to display and to hand to
/// `ssh`: non-empty, at most [`MAX_HOST_LEN`] bytes, ASCII alphanumerics
/// plus `.`/`-` only, no leading/trailing separator. Deliberately NOT a
/// full RFC 1123 validator — the point is bounding untrusted display data
/// and refusing shell/URL metacharacters, not certifying resolvability.
/// Pure.
pub fn valid_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_HOST_LEN
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !s.starts_with(['.', '-'])
        && !s.ends_with(['.', '-'])
}

/// A POSIX-portable login shape: starts with a lowercase letter or `_`,
/// continues with lowercase alphanumerics/`_`/`-`, at most
/// [`MAX_USER_LEN`] bytes. The same "bound untrusted data, refuse
/// metacharacters" stance as [`valid_host`]. Pure.
pub fn valid_user(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && s.len() <= MAX_USER_LEN
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Parse and fully validate one raw line heard off the UDP socket — the
/// ONE gate every field crosses before a caller may look at it (house
/// rule 4): the size cap first (cheapest check, on raw bytes, before a
/// single byte reaches a JSON parser), then the parse itself, then `v`,
/// `name` ([`crate::peer_store::valid_peer_name`]), `host`
/// ([`valid_host`]), and `user` ([`valid_user`]) — in that order,
/// short-circuiting on the first failure. `peer discover`/`peer invite`
/// never display a line that fails any one of these; they only ever
/// increment a dropped count.
pub fn parse_and_validate(line: &str) -> Result<Advertisement, RejectReason> {
    if line.len() > MAX_LINE_BYTES {
        return Err(RejectReason::TooLarge);
    }
    let a: Advertisement = serde_json::from_str(line).map_err(|_| RejectReason::Unparseable)?;
    if a.v != VERSION {
        return Err(RejectReason::WrongVersion);
    }
    if !crate::peer_store::valid_peer_name(&a.name) {
        return Err(RejectReason::InvalidName);
    }
    if !valid_host(&a.host) {
        return Err(RejectReason::InvalidHost);
    }
    if !valid_user(&a.user) {
        return Err(RejectReason::InvalidUser);
    }
    Ok(a)
}

// ── The advertise switch ─────────────────────────────────────────────────
//
// `aoide peer advertise on|off` (task #120): whether THIS instance emits
// advertisements at all. A tiny state file rather than a config framework
// — `state/advertise.json`, written atomically like every other state
// file this crate owns, read by the emitting process (`a2a serve`'s
// advertise thread) on every tick so a toggle lands without a restart.
// Absent file = OFF (a box advertises only when told to — the same
// posture as doors staying loopback-bound). The `--discovery-advertise`
// flag / `AOIDE_DISCOVERY_ADVERTISE` env on `a2a serve` still force the
// emitter on for that process's lifetime (the nix-declarative path); this
// file is the runtime switch beside them, OR'd in, never a replacement.

/// The switch file's own schema version — bumped only on an incompatible
/// shape change, same stance as every other `schemaVersion` this crate
/// writes.
const SWITCH_SCHEMA_VERSION: &str = "0";

#[derive(Serialize, Deserialize)]
struct SwitchFile {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    enabled: bool,
}

fn switch_path() -> std::path::PathBuf {
    crate::fs::state_dir().join("advertise.json")
}

/// Whether this instance's advertise switch is on. Tolerate-missing: an
/// absent or unreadable/unparseable file is simply OFF (the default),
/// never an error — the same additive stance `peer_store::load_peers`
/// holds for its own file.
pub fn enabled() -> bool {
    let Ok(raw) = std::fs::read_to_string(switch_path()) else {
        return false;
    };
    serde_json::from_str::<SwitchFile>(&raw).map(|f| f.enabled).unwrap_or(false)
}

/// Flip the advertise switch, returning what it previously was so the
/// caller can report "changed" vs "already so" (`peer advertise`'s
/// idempotence contract). Atomic write via [`crate::fs::atomic_write`];
/// creates `state/` on first use like every other writer there.
pub fn set_enabled(on: bool) -> std::io::Result<bool> {
    let previous = enabled();
    let path = switch_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = SwitchFile { schema_version: SWITCH_SCHEMA_VERSION.to_string(), enabled: on };
    let line = serde_json::to_string(&file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    crate::fs::atomic_write(&path, &line)?;
    Ok(previous)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Advertisement {
        build("yomi-strix", "yomi-strix", "khoa")
    }

    #[test]
    fn encode_then_parse_and_validate_round_trips() {
        let a = sample();
        let line = encode(&a).expect("a well-formed advertisement always encodes");
        let parsed =
            parse_and_validate(&line).expect("a genuine encoded advertisement always validates");
        assert_eq!(parsed, a);
    }

    #[test]
    fn a_bad_name_is_dropped_and_never_touches_the_other_checks() {
        let mut a = sample();
        a.name = "../evil".to_string();
        let line = serde_json::to_string(&a).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::InvalidName));
    }

    #[test]
    fn a_bad_host_is_dropped() {
        for host in ["", "evil host", "host;rm -rf /", ".leading-dot", "trailing-dot.", &"x".repeat(254)] {
            let mut a = sample();
            a.host = host.to_string();
            let line = serde_json::to_string(&a).unwrap();
            assert_eq!(parse_and_validate(&line), Err(RejectReason::InvalidHost), "host {host:?}");
        }
    }

    #[test]
    fn a_bad_user_is_dropped() {
        for user in ["", "Root", "1user", "user name", "user;id", &"x".repeat(33)] {
            let mut a = sample();
            a.user = user.to_string();
            let line = serde_json::to_string(&a).unwrap();
            assert_eq!(parse_and_validate(&line), Err(RejectReason::InvalidUser), "user {user:?}");
        }
    }

    #[test]
    fn an_oversize_line_is_dropped_before_any_parse() {
        let huge = "x".repeat(MAX_LINE_BYTES + 1);
        assert_eq!(parse_and_validate(&huge), Err(RejectReason::TooLarge));

        // An advertisement whose host alone pushes the WHOLE line over the
        // cap is dropped the same way, proving the check is on the raw
        // line, not the parsed struct.
        let mut a = sample();
        a.host = "x".repeat(MAX_LINE_BYTES);
        let line = serde_json::to_string(&a).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::TooLarge));
    }

    #[test]
    fn an_unparseable_line_is_dropped() {
        assert_eq!(parse_and_validate("not json"), Err(RejectReason::Unparseable));
        assert_eq!(parse_and_validate("{\"v\":2}"), Err(RejectReason::Unparseable));
    }

    #[test]
    fn a_v1_line_with_the_old_field_set_is_dropped_as_wrong_version() {
        // Exactly what a not-yet-rebuilt v1 advertiser still multicasts:
        // fpr/url instead of host/user. serde's deny-nothing default would
        // otherwise happily parse a v1 line missing host/user as
        // Unparseable — the version check must never be reached with a
        // half-compatible shape presented as current.
        let v1 = r#"{"v":1,"name":"yomi-strix","fpr":"aa:bb:cc:dd:ee:ff:00:11","url":"http://yomi-strix:8710/"}"#;
        assert!(parse_and_validate(v1).is_err());
    }

    #[test]
    fn a_future_protocol_version_is_dropped() {
        let mut a = sample();
        a.v = 3;
        let line = serde_json::to_string(&a).unwrap();
        assert_eq!(parse_and_validate(&line), Err(RejectReason::WrongVersion));
    }

    #[test]
    fn encode_refuses_an_advertisement_whose_line_would_exceed_the_cap() {
        let mut a = sample();
        a.host = "x".repeat(MAX_LINE_BYTES);
        assert_eq!(encode(&a), None);
    }

    #[test]
    fn valid_host_accepts_hostnames_and_dotted_quads_and_rejects_metacharacters() {
        assert!(valid_host("yomi-strix"));
        assert!(valid_host("192.168.1.202"));
        assert!(valid_host("box-a.lan"));
        assert!(!valid_host(""));
        assert!(!valid_host("host name"));
        assert!(!valid_host("host/path"));
        assert!(!valid_host("host`id`"));
    }

    #[test]
    fn valid_user_accepts_posix_logins_and_rejects_everything_else() {
        assert!(valid_user("khoa"));
        assert!(valid_user("_svc"));
        assert!(valid_user("agent-7"));
        assert!(!valid_user(""));
        assert!(!valid_user("Root"));
        assert!(!valid_user("9lives"));
        assert!(!valid_user("user name"));
    }

    // ── The advertise switch (state/advertise.json) ──────────────────────

    /// Point AOIDE_STATE_DIR at a fresh temp dir for one closure —
    /// process-env mutation, so serialized on the shared env lock like
    /// every other env-touching test in this crate.
    fn with_temp_state<F: FnOnce()>(tag: &str, f: F) {
        let _guard = crate::env_lock().lock().unwrap();
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "aoide-advertise-switch-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let saved = std::env::var("AOIDE_STATE_DIR").ok();
        std::env::set_var("AOIDE_STATE_DIR", &dir);
        f();
        match saved {
            Some(v) => std::env::set_var("AOIDE_STATE_DIR", v),
            None => std::env::remove_var("AOIDE_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_switch_defaults_off_and_flips_idempotently() {
        with_temp_state("flip", || {
            assert!(!enabled(), "absent file = OFF, the default posture");
            assert!(!set_enabled(true).unwrap(), "previous state was off");
            assert!(enabled());
            assert!(set_enabled(true).unwrap(), "already on — idempotent, previous reported true");
            assert!(set_enabled(false).unwrap());
            assert!(!enabled());
            assert!(!set_enabled(false).unwrap(), "already off");
        });
    }

    #[test]
    fn a_corrupt_switch_file_reads_as_off_never_an_error() {
        with_temp_state("corrupt", || {
            let path = crate::fs::state_dir().join("advertise.json");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "not json at all").unwrap();
            assert!(!enabled());
        });
    }
}
