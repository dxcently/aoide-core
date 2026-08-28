//! The discovery advertisement's SEND half (P-P6 + task #120,
//! `docs/architecture/PAIRING.md`'s "Discovery (advertise-but-locked)"
//! section): a background thread `a2a::serve` always starts, which emits an
//! `aoide_storage::advertise::Advertisement` line by UDP broadcast to the
//! fixed port on a jittered ~30s cadence — but ONLY on ticks where
//! advertising is actually switched on. The switch is read EVERY tick
//! (`aoide_storage::advertise::enabled`, flipped by `aoide peer advertise
//! on|off`), so an operator's toggle lands within one cadence, no restart;
//! `--discovery-advertise`/`AOIDE_DISCOVERY_ADVERTISE`
//! (`a2a::resolve_discovery_advertise`, the nix-declarative path) force it
//! on for this process's whole lifetime, OR'd with the switch. Both off —
//! the default — means the thread ticks silently and sends nothing.
//!
//! **Broadcast, not multicast** (task #120's #106 fix): the original
//! multicast group never crossed the User's router — verified live
//! 2026-08-27, each box heard only itself — and a LAN this size needs none
//! of multicast's efficiency. A limited-broadcast (`255.255.255.255`)
//! datagram needs no group membership on either end, no interface
//! pinning, and no multicast-capability probing; the listener is a plain
//! `0.0.0.0` bind.
//!
//! **The RECEIVE half lives in `aoide-client`** (`discover::run_sweep`),
//! never here — this crate is inbound/serve-only (this crate's own
//! `AGENTS.md`); sending an advertisement is the one thing the
//! door-owning PROCESS itself does, never something a client-side command
//! triggers. **No resident listener exists anywhere** (PAIRING.md,
//! verbatim) — hearing an advertisement is always an on-demand `peer
//! discover`/`peer invite` sweep, never something `a2a serve` does on its
//! own.
//!
//! **Rendezvous, not authentication** (`aoide_storage::advertise`'s module
//! doc holds the full statement): the line carries this instance's name
//! and its ssh hop info (`host`/`user`) only — never a door URL (doors are
//! loopback-bound; ssh is the only cross-box transport), never an identity
//! fingerprint or key. No identity file is ever touched to advertise.
//!
//! **Fallible spawn** (`server/AGENTS.md`'s `daemon.rs` discipline — the
//! fallible `thread::Builder::spawn`, not `a2a.rs`'s own plain
//! `thread::spawn` for connection handlers, which that same doc explicitly
//! reserves for a NEW socket-based door, not a background worker thread
//! like this one): a refused OS thread here costs discovery only, never
//! the door itself — `a2a serve` keeps answering requests exactly as it
//! would with advertising off.
//!
//! **Clean shutdown needs no signal.** Each sending tick binds a FRESH
//! ephemeral UDP socket, sends one line, and drops it — nothing here holds
//! a long-lived resource between ticks, so there is nothing to leak or
//! close explicitly; the thread (and the process) simply stops existing
//! when `a2a serve` itself exits, the same as every other detached worker
//! thread in this crate.

use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Base cadence between advertisements (PAIRING.md: "~30s").
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

/// One send: encode this instance's own advertisement and fire it at the
/// broadcast destination. Binds a brand-new ephemeral UDP socket every
/// call (with `SO_BROADCAST` set — a plain socket refuses a broadcast
/// destination outright) — an advertisement is fire-and-forget, never a
/// connection, so there is no reason to hold one open between ticks.
/// `send_to` on a UDP socket never blocks waiting for a listener (unlike
/// TCP's connect handshake), so this is bounded work per tick, the same
/// shape `aoide-server`'s own daemon producers hold
/// (`producers::SecretsMirror::tick`). A send failure (no route, an
/// interface down, a sandboxed network namespace, …) is logged and
/// dropped — it costs this one tick's advertisement, never the advertise
/// thread itself.
fn send_once(name: &str, host: &str, user: &str) {
    let advertisement = aoide_storage::advertise::build(name, host, user);
    let Some(line) = aoide_storage::advertise::encode(&advertisement) else {
        eprintln!(
            "aoide a2a discovery: this instance's own advertisement line exceeds the \
             {}-byte cap — refusing to send a truncated one (this is a bug, not \
             a configuration error)",
            aoide_storage::advertise::MAX_LINE_BYTES
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
    if let Err(e) = socket.set_broadcast(true) {
        eprintln!("aoide a2a discovery: enabling broadcast on the outbound socket: {e}");
        return;
    }
    let dest = (aoide_storage::advertise::BROADCAST_ADDR, aoide_storage::advertise::PORT);
    if let Err(e) = socket.send_to(line.as_bytes(), dest) {
        eprintln!("aoide a2a discovery: sending advertisement: {e}");
    }
}

/// Start the advertise thread. `name`/`host`/`user` are captured once at
/// `a2a serve` launch — the same "resolved once, held for the server's
/// whole lifetime" shape every other `resolve_*`-derived value `serve`
/// already threads through unchanged (an operator who wants to change any
/// of them restarts the server, same as `--bind`/`--port` today).
/// `force_on` is `resolve_discovery_advertise`'s launch-time answer;
/// whether a given tick actually SENDS is `force_on ||
/// aoide_storage::advertise::enabled()`, the switch read fresh every tick
/// (module doc). Returns `None` (never fatal to the caller) when the OS
/// refuses to spawn the thread at all — see the module doc's
/// fallible-spawn note.
pub fn spawn_advertiser(
    name: &str,
    host: &str,
    user: &str,
    force_on: bool,
) -> Option<std::thread::JoinHandle<()>> {
    let name = name.to_string();
    let host = host.to_string();
    let user = user.to_string();
    match std::thread::Builder::new()
        .name("aoide-discovery-advertise".to_string())
        .spawn(move || loop {
            if force_on || aoide_storage::advertise::enabled() {
                send_once(&name, &host, &user);
            }
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
    fn send_once_on_an_oversize_advertisement_never_panics_and_sends_nothing_malformed() {
        // A host long enough to push the whole encoded line over
        // `MAX_LINE_BYTES` — `send_once` must log and return, never panic
        // or attempt to send a truncated line. (A well-formed line's actual
        // broadcast send is exercised only outside sandboxes — a loopback-
        // only network namespace has no broadcast route, and `send_once`
        // logs-and-drops that too.)
        let huge_host = "x".repeat(4096);
        send_once("box-a", &huge_host, "khoa");
    }
}
