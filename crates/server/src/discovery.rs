//! The discovery beacon's ADVERTISE half (P-P6, `docs/architecture/
//! PAIRING.md`'s "Discovery (advertise-but-locked)" section): a background
//! thread `a2a::serve` starts ONLY when discovery advertising is turned on
//! (`a2a::resolve_discovery_advertise` — off by default), sending an
//! `aoide_storage::beacon::Beacon` line to the fixed multicast group+port
//! on a jittered ~30s cadence for as long as `a2a serve` itself runs.
//!
//! **The RECEIVE half lives in `aoide-client`** (`discover::run_sweep`),
//! never here — this crate is inbound/serve-only (this crate's own
//! `AGENTS.md`); sending a beacon is the one thing the door-owning PROCESS
//! itself does, never something a client-side command triggers. **No
//! resident listener exists anywhere** (PAIRING.md, verbatim) — hearing a
//! beacon is always an on-demand `peer discover`/`peer invite` sweep, never
//! something `a2a serve` does on its own.
//!
//! **Fallible spawn** (`server/AGENTS.md`'s `daemon.rs` discipline — the
//! fallible `thread::Builder::spawn`, not `a2a.rs`'s own plain
//! `thread::spawn` for connection handlers, which that same doc explicitly
//! reserves for a NEW socket-based door, not a background worker thread
//! like this one): a refused OS thread here costs discovery only, never
//! the door itself — `a2a serve` keeps answering requests exactly as it
//! would with advertising off.
//!
//! **Clean shutdown needs no signal.** Each tick binds a FRESH ephemeral
//! UDP socket, sends one line, and drops it — nothing here holds a
//! long-lived resource between ticks, so there is nothing to leak or close
//! explicitly; the thread (and the process) simply stops existing when
//! `a2a serve` itself exits, the same as every other detached worker
//! thread in this crate.

use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Base cadence between beacons (PAIRING.md: "~30s").
const INTERVAL: Duration = Duration::from_secs(30);

/// Jitter span ADDED on top of [`INTERVAL`] each tick, so a fleet of
/// advertisers on the same LAN don't all key up in lockstep.
const JITTER: Duration = Duration::from_secs(10);

/// A jitter source with no new dependency (the brief: "zero new deps —
/// std::net UdpSocket... is the whole toolbox") — the low bits of the wall
/// clock's own nanosecond component. Not cryptographic, and doesn't need
/// to be: the only thing riding on this is when a background thread wakes
/// up next, never anything security-relevant (contrast
/// `aoide_storage::pairing::random_hex`, which mints values that DO feed a
/// commitment/SAS transcript and rightly goes through the system CSPRNG
/// instead).
fn jitter() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    Duration::from_millis(nanos % (JITTER.as_millis() as u64).max(1))
}

/// One tick: encode this instance's own beacon and fire it at the fixed
/// multicast destination. Binds a brand-new ephemeral UDP socket every
/// call — a multicast beacon is fire-and-forget, never a connection, so
/// there is no reason to hold one open between ticks. `send_to` on a UDP
/// socket never blocks waiting for a listener (unlike TCP's connect
/// handshake), so this is bounded work per tick, the same shape
/// `aoide-server`'s own daemon producers hold
/// (`producers::SecretsMirror::tick`). A send failure (no route, an
/// interface down, …) is logged and dropped — it costs this one tick's
/// beacon, never the advertise thread itself.
fn send_once(name: &str, fpr: &str, url: &str) {
    let beacon = aoide_storage::beacon::build(name, fpr, url);
    let Some(line) = aoide_storage::beacon::encode(&beacon) else {
        eprintln!(
            "aoide a2a discovery: this instance's own beacon line exceeds the \
             {}-byte cap — refusing to send a truncated one (this is a bug, not \
             a configuration error)",
            aoide_storage::beacon::MAX_LINE_BYTES
        );
        return;
    };
    let socket = match UdpSocket::bind(("0.0.0.0", 0)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aoide a2a discovery: binding an outbound UDP socket: {e}");
            return;
        }
    };
    let dest = (aoide_storage::beacon::GROUP, aoide_storage::beacon::PORT);
    if let Err(e) = socket.send_to(line.as_bytes(), dest) {
        eprintln!("aoide a2a discovery: sending beacon: {e}");
    }
}

/// Start the advertise thread. `name`/`fpr`/`url` are captured once at
/// `a2a serve` launch — the same "resolved once, held for the server's
/// whole lifetime" shape every other `resolve_*`-derived value `serve`
/// already threads through unchanged (an operator who wants to change any
/// of them restarts the server, same as `--bind`/`--port` today). Returns
/// `None` (never fatal to the caller) when the OS refuses to spawn the
/// thread at all — see the module doc's fallible-spawn note.
pub fn spawn_advertiser(name: &str, fpr: &str, url: &str) -> Option<std::thread::JoinHandle<()>> {
    let name = name.to_string();
    let fpr = fpr.to_string();
    let url = url.to_string();
    match std::thread::Builder::new()
        .name("aoide-discovery-advertise".to_string())
        .spawn(move || loop {
            send_once(&name, &fpr, &url);
            std::thread::sleep(INTERVAL + jitter());
        }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!(
                "aoide a2a discovery: failed to spawn the advertise thread: {e} — \
                 continuing without discovery advertising"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_never_exceeds_its_own_span() {
        for _ in 0..50 {
            assert!(jitter() < JITTER, "jitter must stay under the configured span");
        }
    }

    #[test]
    fn send_once_on_an_oversize_beacon_never_panics_and_sends_nothing_malformed() {
        // A url long enough to push the whole encoded line over
        // `MAX_LINE_BYTES` — `send_once` must log and return, never panic
        // or attempt to send a truncated line.
        let huge_url = format!("http://{}/", "x".repeat(4096));
        send_once("box-a", "aa:bb:cc:dd:ee:ff:00:11", &huge_url);
    }
}
