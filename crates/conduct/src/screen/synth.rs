//! The pointer-synthesis boundary's HOW half (khoa, 2026-08-17, Phase A of
//! the pointer-emulation workstream; hardened same-day per Opus's Phase A
//! review) — replaces Phase 2's `wlrctl` shell-out (`run_wlrctl_pointer`,
//! `point.rs`) with a native `zwlr_virtual_pointer_v1` client speaking
//! Wayland directly. [`synthesize`] is the ONLY function in the entire
//! workspace allowed to name a `wayland_client` / `wayland_protocols_wlr`
//! type — everything above it in the call chain (`point.rs`) still decides
//! WHAT to synthesize (delta math, button choice, scroll notches) via the
//! pure [`Seq`] builders there; this module decides HOW. [`PointerError`]'s
//! reason codes stay exactly as backend-agnostic as they were behind the
//! wlrctl boundary (`pointer-*`, never naming the backend) — moving here
//! changes nothing about that discipline, only who implements it.
//!
//! ── Why a native client, not a second shell-out (khoa's Phase A brief)
//! ────────────────────────────────────────────────────────────────────────
//! `wlrctl` itself is a thin wrapper around exactly this protocol; shelling
//! out to it cost a process spawn plus a second point of failure (wlrctl
//! missing from PATH) for work this crate can do directly with one
//! already-open socket per call. The wire protocol
//! (`wlr-virtual-pointer-unstable-v1`) is unchanged from what `wlrctl` used
//! — this is a transport swap, not a behavior change; every verb in
//! `point.rs` produces the exact same motion/button/scroll events on the
//! wire as before, modulo the scroll-magnitude divergence documented at
//! [`WHEEL_VALUE`] below.
//!
//! ── Connection lifecycle, one per call (khoa's Phase A brief) ────────────
//! [`synthesize`] connects fresh, walks the given [`Seq`], and disconnects —
//! no persistent connection is cached across calls. This mirrors
//! `run_wlrctl_pointer`'s own one-shot-process lifecycle (a `wlrctl pointer
//! move` process also connected, acted, and exited every single call) rather
//! than introducing a new class of "stale connection" bug a persistent
//! handle would invite; nothing in `point.rs`'s verbs calls `synthesize`
//! often enough for the extra connect/bind cost to matter. **Exception**: a
//! [`Seq`] with no [`Step`]s at all returns `Ok(())` before connecting to
//! anything — see the empty-Seq short-circuit below.
//!
//! ── The empty-`Seq` short-circuit (Opus review, L4) ───────────────────────
//! `synthesize(&Seq(vec![]))` returns `Ok(())` immediately, before opening a
//! connection, binding anything, or creating/destroying a virtual pointer
//! object. A create-then-immediately-destroy with zero events in between
//! would be pure overhead for a call site that already computed there was
//! nothing to send (`move_seq(0, 0)`, `scroll_seq(0, 0)`, `click_seq(_, 0)`)
//! — and on some compositors, rapid virtual-input-device create/destroy
//! churn is itself an event other listeners can observe, which a genuine
//! no-op has no business generating.
//!
//! ── The seatless-create fallback (khoa's Phase A brief) ──────────────────
//! `zwlr_virtual_pointer_manager_v1.create_virtual_pointer`'s `seat`
//! argument is nullable by protocol design ("the optional seat is a
//! suggestion to the compositor") and every wlroots compositor this
//! workstream targets (Hyprland foremost) accepts `None` unconditionally —
//! so [`synthesize`] tries that first, always. The protocol defines no
//! explicit error for a compositor that refuses anyway; the only signal
//! available is the connection itself dying (Wayland surfaces a fatal
//! protocol violation by tearing down the whole `wl_display`, not by
//! rejecting one request), which [`connect_and_create`] catches with an
//! immediate flush+roundtrip right after creation, BEFORE any of the
//! caller's [`Step`]s are sent. On that specific failure — and only that
//! one, not a missing display or a missing manager global, neither of which
//! a seat would fix — [`synthesize`] reconnects from scratch and retries
//! once with an explicit `wl_seat` bound from the registry. Untested live
//! (no compositor in this workstream's reach has ever been observed to need
//! it); present because the brief asked for the fallback to exist, not
//! because it's been seen to fire.
//!
//! ── The stuck-button invariant (khoa's Phase A brief, an exit criterion —
//! Opus's review confirmed it holds on every path) ─────────────────────────
//! [`synthesize`] tracks which button codes are currently "down" as it walks
//! a [`Seq`], and — on every path out of the walk, success or failure alike
//! — releases whichever are still down, closes that release in its own
//! `frame()`, and only then destroys the virtual pointer and disconnects.
//! Implemented as a single unconditional exit point after the walk (see
//! [`synthesize`]'s body) rather than a `Drop` guard: nothing in the walk
//! can panic (every `wayland-client` call it makes returns a `Result`, none
//! of them a bare `unwrap`), so there is no unwind path a `Drop` guard would
//! catch that a single post-walk cleanup block doesn't already cover, and a
//! guard holding `&mut EventQueue`/`&mut State` for the walk's whole
//! duration would fight the borrow checker against the walk's own use of
//! those same handles for no behavioral gain. A compositor tearing down a
//! virtual pointer with a button still logically held leaves that button
//! stuck on a desk a human is using — this is the hazard the invariant
//! exists to close.
//!
//! ── One `frame()` per wheel notch (Opus review, B1 — a blocking defect)
//! ────────────────────────────────────────────────────────────────────────
//! `wl_pointer`'s own contract (and every wlroots-class compositor's
//! implementation of it) allows at most one `axis_discrete` per axis inside
//! a single `frame()` — a second one for the same axis before the next
//! `frame()` overwrites the first rather than accumulating. The first cut of
//! this module got that wrong: it sent `axis_source` once, then looped N
//! notches each doing `axis`+`axis_discrete` into the SAME frame, then one
//! `frame()` at the end — so `scroll 10` synthesized ten `axis_discrete`
//! requests but the compositor only ever saw the last one, a single detent.
//! `walk` now sends `axis_source` + `axis` + `axis_discrete` + `frame()`
//! once PER NOTCH (`axis_source` is per-frame state in this protocol, not
//! sticky across frames, so it has to be resent every time) and flushes once
//! after the whole per-notch loop, not per notch — the flush is about
//! getting bytes onto the wire promptly, not about frame boundaries, and one
//! flush for N frames is exactly as correct as N flushes here.
//!
//! ── `time` is a real monotonic clock, not per-call-relative (Opus review,
//! L1) ───────────────────────────────────────────────────────────────────
//! Every request needing a `time` argument gets milliseconds since an
//! arbitrary but fixed point on `CLOCK_MONOTONIC` (via `libc::clock_gettime`,
//! `libc` already a workspace dependency — see [`now_ms`]), truncated to
//! `u32` (Wayland's own field width for this; wraps roughly every 49.7 days
//! of host uptime, a property of the protocol itself, not a bug this module
//! introduces). The first cut used an `Instant` captured fresh at the start
//! of each `synthesize()` call, so every call's own timestamps started back
//! near 0 — meaning two separate `screen point click` invocations issued
//! close together on the wire clock could carry near-identical `time`
//! values even though real wall time had moved on between them, which is
//! exactly the signal a toolkit's double-click heuristic reads to decide
//! "these two presses are one gesture." A shared, ever-advancing clock
//! (still never wired to wall-clock/`CLOCK_REALTIME`, which Wayland
//! explicitly forbids using here) makes every call's timestamps honest
//! relative to each other, not just internally self-consistent.
//!
//! ── The double roundtrip, and manager/pointer destroy symmetry (khoa's
//! Phase A brief; L3 from Opus's review) ───────────────────────────────────
//! `frame()` closes every logical event group (one per [`Step`], except a
//! multi-notch [`Step::Wheel`], which is now one group PER NOTCH — see
//! above); `conn.flush()` follows every `Step` (khoa's Phase B nit fix,
//! 2026-08-17: the prior wording said "every group", which is exactly wrong
//! for the wheel case — one multi-notch `Step::Wheel` opens/closes several
//! frames but `walk` flushes it only once, after the whole per-notch loop,
//! not once per frame) so requests actually leave the
//! socket rather than sitting buffered (retried on a transient `WouldBlock`
//! rather than aborting the whole `Seq` over it — see [`flush_retrying`]).
//! Two `queue.roundtrip()`s bookend the very end — one right after the last
//! group, one after teardown — closing a latent race: a caller like
//! `point_move` immediately re-reads the cursor via `hyprctl cursorpos`
//! after a successful [`synthesize`] call, and that query must not be able
//! to outrun the compositor actually having processed the motion yet.
//! Teardown itself destroys the virtual pointer object AND THEN the manager
//! binding — one extra `destroy()` request for symmetry (both objects this
//! module created get explicitly destroyed, not just the one with the more
//! obvious "leaving a virtual input device around is bad" hazard); it costs
//! one more request on a connection about to close anyway.
//!
//! ── Flush retries on `WouldBlock` (Opus review, M1) ───────────────────────
//! `Connection::flush()` can return `Err(WaylandError::Io(e))` with
//! `e.kind() == WouldBlock` when the socket's send buffer is momentarily
//! full — per wayland-backend's own docs this is transient, not a dead
//! connection, unlike every other `WaylandError`. Treating it as fatal (the
//! first cut's behavior) risked two real hazards: aborting a [`Seq`] mid-walk
//! over a condition that would have cleared itself in microseconds, and —
//! worse — the final cleanup flush (the one that puts a stuck-button release
//! on the wire) silently failing to send those bytes at all, so the process
//! exits believing it released a button it never actually told the
//! compositor to release. [`flush_retrying`] retries a `WouldBlock` for up
//! to 50ms in short sleeps before giving up and surfacing a real
//! [`PointerError::Failed`] — bounded so a genuinely dead socket still fails
//! fast rather than hanging.
//!
//! ── NOT unit-tested (khoa's Phase A brief) ────────────────────────────────
//! [`synthesize`] itself opens a real Wayland socket and is not unit-tested
//! — same split this crate already draws around `capture::capture_image`
//! and `hypr::run_hyprctl_json`: the pure logic feeding it ([`Seq`]
//! construction in `point.rs`) is exhaustively tested, the real I/O at the
//! boundary is not. Never invoked live by this phase's own executor either
//! (a human may be at the desk this runs on) — see `point.rs`'s module
//! header for the inherited HARD RULE.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use wayland_client::backend::WaylandError;
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_pointer::{
    Axis as WlAxis, AxisSource as WlAxisSource, ButtonState,
};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle};
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1;
use wayland_protocols_wlr::virtual_pointer::v1::client::zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1;

// ── The WHAT vocabulary — what `point.rs` hands down ──────────────────────

/// Which scroll axis a [`Step::Wheel`] moves — `wl_pointer`'s own two-axis
/// vocabulary, named here rather than re-exporting `wl_pointer::Axis`
/// directly so nothing above this module ever needs to name a
/// `wayland_client` type (the whole point of the boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    Vertical,
    Horizontal,
}

/// One synthesized pointer event, backend-agnostic — `point.rs`'s builders
/// (`move_seq`/`click_seq`/`scroll_seq`) assemble these; nothing about this
/// type names Wayland. All four variants hold only `Copy` data, so `Step`
/// itself derives `Copy` — a [`Seq`] is cheap to build and compare in tests.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Step {
    /// Relative motion, compositor-space units (matches `move_delta`'s
    /// output — a `(dx, dy)` pair already computed against the current
    /// cursor position).
    Motion { dx: i64, dy: i64 },
    /// A button press or release. `code` is a Linux input-event-codes
    /// constant (`BTN_LEFT` etc, see [`super::point::button_code`]) — this
    /// module never interprets the number, only forwards it.
    Button { code: u32, pressed: bool },
    /// `notches` wheel detents on `axis`; sign is direction (matches
    /// `point.rs`'s existing "positive = down/right" convention). Zero
    /// notches is meaningless and never constructed by `scroll_seq` (it
    /// yields an empty [`Seq`] instead), but [`walk`] treats it as a no-op
    /// rather than trusting that invariant blindly. `point.rs`'s
    /// `scroll_seq` also clamps `notches` to a bounded range before this
    /// ever gets built — see its own doc.
    Wheel { axis: Axis, notches: i64 },
    /// A deliberate pause mid-sequence — `click_seq` uses this between a
    /// press and the next click's press so a compositor sees two distinct
    /// clicks rather than one held-down blur.
    Pause { ms: u64 },
}

/// An ordered list of [`Step`]s — one call to [`synthesize`] walks exactly
/// one `Seq`, start to finish (or fails partway and cleans up — see the
/// module header's stuck-button invariant). An empty `Seq` is a legitimate,
/// cheap no-op — see the module header's empty-`Seq` short-circuit.
#[derive(Debug, Clone, PartialEq)]
pub struct Seq(pub Vec<Step>);

// ── Errors — moved here verbatim from `point.rs`'s Phase 2 boundary ───────

/// One synthesis attempt's failure. Split the same way `CaptureError`/
/// `HyprError` already split theirs (spawn/connect-failed vs
/// ran-but-refused) — unchanged in shape from the wlrctl-era `PointerError`
/// this replaces; only the backend behind it moved.
#[derive(Debug, Clone, PartialEq)]
pub enum PointerError {
    /// Couldn't even reach a compositor: no `WAYLAND_DISPLAY`, the connect
    /// itself failed, or the compositor doesn't advertise a virtual-pointer
    /// manager (or, on the seat-fallback retry, no `wl_seat` global either).
    Unavailable(String),
    /// Connected and bound fine, but a request was refused or the
    /// connection died partway through a [`Seq`].
    Failed(String),
}

impl PointerError {
    /// Backend-agnostic reason code — `pointer-*`, never naming the backend
    /// (khoa's Phase 1 review, D2; unchanged by this phase's transport
    /// swap — a caller must never learn which tool did the work from this
    /// code, wlrctl or native, only from `detail()` if it wants to).
    pub fn reason(&self) -> &'static str {
        match self {
            PointerError::Unavailable(_) => "pointer-unavailable",
            PointerError::Failed(_) => "pointer-failed",
        }
    }
    /// The actual backend detail (a connect error, a protocol error, …) —
    /// genuinely useful troubleshooting text; unlike `reason()`, allowed to
    /// say whatever the backend actually said.
    pub fn detail(&self) -> &str {
        match self {
            PointerError::Unavailable(s) | PointerError::Failed(s) => s,
        }
    }
}

// ── Tunables ────────────────────────────────────────────────────────────

/// Magnitude sent on both `axis` (the continuous value) and `axis_discrete`
/// (paired with `discrete = ±1`) per wheel notch.
///
/// **Deliberate divergence from wlrctl's measured `n * 5`** (`point.rs`'s
/// old `scroll_notches`, now deleted): that scaling was wlrctl's own
/// invention, not a compositor requirement — `wl_pointer`'s documented
/// convention for one physical wheel click is `120/8 = 15.0` continuous
/// units alongside `discrete = 1`. `15.0` here means **n notches now means
/// n real wheel detents**, not n arbitrary wlrctl units; Phase C (this
/// workstream's live-verification phase) confirms the magnitude feels right
/// against a real compositor before this is called settled.
const WHEEL_VALUE: f64 = 15.0;

/// Defense-in-depth bound on wheel notches PER [`Step::Wheel`] (khoa's Phase
/// B review nit 3, pointer-emulation workstream, 2026-08-17). `walk`'s Wheel
/// arm used to iterate `notches.unsigned_abs()` trusting that whatever built
/// the `Seq` had already clamped it — true of Phase A's only caller
/// (`point.rs`'s `clamp_notches`), but Phase B wires a second CLI-reachable
/// path into the same loop (two-axis scroll's new `dx`, clamped by the same
/// `clamp_notches` but now a second call site trusting it did its job), so
/// the loop now defends itself instead of trusting every future caller got
/// it right. (`--count` is a different Phase B addition entirely — it drives
/// `click_seq`'s `Step::Button` loop, never this one.) `synth.rs` must not
/// import from `point.rs` (this module's own layering rule, see the
/// header), so the sharing runs the other direction: `point.rs`'s
/// `MAX_SCROLL_NOTCHES` is DEFINED as this constant rather than merely equal
/// to it, so the two bounds cannot drift apart.
pub const MAX_WHEEL_NOTCHES_PER_STEP: i64 = 100;

/// Upper bound on how long [`flush_retrying`] keeps retrying a transient
/// `WouldBlock` before giving up and surfacing a real failure.
const FLUSH_RETRY_BUDGET: Duration = Duration::from_millis(50);
/// How long each retry sleeps before trying the flush again.
const FLUSH_RETRY_SLEEP: Duration = Duration::from_millis(2);

// ── Dispatch plumbing — every interface this module touches, empty bodies
// throughout: `zwlr_virtual_pointer_manager_v1`/`zwlr_virtual_pointer_v1`
// define no events at all (write-only protocols, confirmed against their
// own XML), and `wl_seat`'s events (capabilities/name) carry nothing this
// one-shot fallback path needs. `State` itself carries no data — it exists
// only because `Dispatch` needs a type to implement it on. ─────────────────

struct State;

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _state: &mut Self,
        _proxy: &WlRegistry,
        _event: wayland_client::protocol::wl_registry::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrVirtualPointerManagerV1, ()> for State {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrVirtualPointerManagerV1,
        _event: <ZwlrVirtualPointerManagerV1 as wayland_client::Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZwlrVirtualPointerV1, ()> for State {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrVirtualPointerV1,
        _event: <ZwlrVirtualPointerV1 as wayland_client::Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlSeat, ()> for State {
    fn event(
        _state: &mut Self,
        _proxy: &WlSeat,
        _event: wayland_client::protocol::wl_seat::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

// ── A real monotonic clock (Opus review, L1) ──────────────────────────────

/// Milliseconds since an arbitrary but fixed point on `CLOCK_MONOTONIC` —
/// NOT restarted per [`synthesize`] call (unlike the `Instant`-since-this-
/// call clock the first cut used), so two calls issued close together on
/// the wire clock carry genuinely different, honestly-ordered `time`
/// values instead of both starting near 0 (see the module header on why
/// that mattered for double-click detection). Truncates to `u32` —
/// Wayland's own field width for `time` — which wraps roughly every 49.7
/// days of host uptime; that is a property of the protocol itself (every
/// `wl_pointer` time field shares it), not a limitation introduced here.
/// Never panics: `CLOCK_MONOTONIC` is unconditionally available on every
/// Linux kernel this crate targets (this whole `screen` module is
/// Linux-only already), and a failure return here (which does not happen
/// in practice) just leaves `ts` at its zero-initialized default rather
/// than reading uninitialized memory.
fn now_ms() -> u32 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, fully owned `timespec` the kernel only
    // writes into via a valid pointer to it; `CLOCK_MONOTONIC` requires no
    // other preconditions.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add((ts.tv_nsec as u64) / 1_000_000) as u32
}

// ── flush, retrying a transient WouldBlock (Opus review, M1) ─────────────

/// `conn.flush()`, but a `WouldBlock` (send buffer momentarily full — see
/// the module header) is retried in short sleeps for up to
/// [`FLUSH_RETRY_BUDGET`] before giving up. Every OTHER `WaylandError`
/// (including a `WouldBlock` that still hasn't cleared once the budget
/// runs out) becomes a [`PointerError::Failed`] immediately — this never
/// hangs indefinitely.
fn flush_retrying(conn: &Connection) -> Result<(), PointerError> {
    let deadline = Instant::now() + FLUSH_RETRY_BUDGET;
    loop {
        match conn.flush() {
            Ok(()) => return Ok(()),
            Err(WaylandError::Io(e))
                if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(FLUSH_RETRY_SLEEP);
            }
            Err(e) => return Err(PointerError::Failed(e.to_string())),
        }
    }
}

// ── Connect + create — the seatless-first, seat-fallback dance ───────────

/// One live connection plus the manager binding and the virtual pointer
/// object created on it, bundled so [`synthesize`] can move all five pieces
/// together through its walk and final teardown.
struct Rig {
    conn: Connection,
    queue: EventQueue<State>,
    state: State,
    manager: ZwlrVirtualPointerManagerV1,
    pointer: ZwlrVirtualPointerV1,
}

/// Connect, bind the virtual-pointer manager, create the virtual pointer
/// (seatless unless `with_seat`), and confirm with an immediate
/// flush+roundtrip that the compositor didn't kill the connection over it —
/// see the module header on why that roundtrip is the only refusal signal
/// this protocol offers. Never panics: every failure mode (no
/// `WAYLAND_DISPLAY`, connect refused, missing manager global, missing
/// `wl_seat` global on the fallback attempt, or a dead connection after
/// create) becomes a [`PointerError`], never an `unwrap`.
fn connect_and_create(with_seat: bool) -> Result<Rig, PointerError> {
    let conn = Connection::connect_to_env()
        .map_err(|e| PointerError::Unavailable(e.to_string()))?;
    let (globals, mut queue) = registry_queue_init::<State>(&conn)
        .map_err(|e| PointerError::Unavailable(e.to_string()))?;
    let qh = queue.handle();

    let manager = globals
        .bind::<ZwlrVirtualPointerManagerV1, _, _>(&qh, 1..=2, ())
        .map_err(|_| {
            PointerError::Unavailable(
                "compositor does not advertise a virtual-pointer manager".to_string(),
            )
        })?;

    let seat = if with_seat {
        Some(globals.bind::<WlSeat, _, _>(&qh, 1..=1, ()).map_err(|_| {
            PointerError::Unavailable(
                "compositor does not advertise a wl_seat global (needed for the \
                 virtual-pointer seat fallback)"
                    .to_string(),
            )
        })?)
    } else {
        None
    };

    let pointer = manager.create_virtual_pointer(seat.as_ref(), &qh, ());
    let mut state = State;
    flush_retrying(&conn)?;
    queue
        .roundtrip(&mut state)
        .map_err(|e| PointerError::Failed(e.to_string()))?;

    Ok(Rig { conn, queue, state, manager, pointer })
}

// ── THE POINTER-SYNTHESIS BOUNDARY (khoa, 2026-08-17, Phase A) ────────────

/// Synthesize every [`Step`] in `seq`, in order, via a native
/// `zwlr_virtual_pointer_v1` client. THE pointer-synthesis boundary's HOW
/// half — see the module header for the full design (the empty-`Seq`
/// short-circuit, seat fallback, the stuck-button invariant, the double
/// roundtrip, flush retries). NOT unit-tested (real socket connect); every
/// pure builder feeding it (`point.rs`'s `move_seq`/`click_seq`/
/// `scroll_seq`) is.
pub fn synthesize(seq: &Seq) -> Result<(), PointerError> {
    if seq.0.is_empty() {
        // No connection opened, nothing created or destroyed — see the
        // module header's empty-Seq short-circuit (Opus review, L4).
        return Ok(());
    }

    let Rig { conn, mut queue, mut state, manager, pointer } = match connect_and_create(false) {
        // Connected and bound fine, but creating the object was refused (the
        // only failure mode a seat could plausibly fix) — retry once, this
        // time with an explicit wl_seat. Any other failure (no display, no
        // manager global) propagates immediately: a seat wouldn't fix those.
        Err(PointerError::Failed(_)) => connect_and_create(true)?,
        other => other?,
    };

    let mut pressed: HashSet<u32> = HashSet::new();

    let outcome = walk(&pointer, &conn, seq, &mut pressed).and_then(|()| {
        // "roundtrip() after the final event" (module header) — confirms the
        // compositor has processed the last logical group before we move on
        // to destroying the object.
        queue
            .roundtrip(&mut state)
            .map(|_| ())
            .map_err(|e| PointerError::Failed(e.to_string()))
    });

    // ── CRITICAL INVARIANT: never return with a button still held ────────
    // Single exit point, reached on every path out of `walk` above (success
    // or failure alike — `outcome`'s value doesn't gate this block at all).
    // See the module header on why this is a plain post-walk block and not
    // a `Drop` guard.
    if !pressed.is_empty() {
        let t = now_ms();
        for code in pressed.drain() {
            pointer.button(t, code, ButtonState::Released);
        }
        pointer.frame();
    }
    // Teardown: pointer object, then the manager binding — symmetry (L3),
    // one more request on a connection that's closing anyway.
    pointer.destroy();
    manager.destroy();
    let closed = flush_retrying(&conn).and_then(|()| {
        // "…AND after destroy()" (module header) — the second half of the
        // double roundtrip; closes the race against a caller's immediate
        // follow-up hyprctl query.
        queue
            .roundtrip(&mut state)
            .map(|_| ())
            .map_err(|e| PointerError::Failed(e.to_string()))
    });

    // The walk's own outcome is the primary failure to report if there is
    // one; a trailing close-sequence failure only surfaces when the walk
    // itself was clean.
    outcome.and(closed)
}

/// Walk `seq`, sending one Wayland request group per [`Step`] (except
/// [`Step::Wheel`], which sends one group PER NOTCH — see the module header,
/// B1) and tracking `pressed` as it goes (the stuck-button invariant's
/// bookkeeping — the caller, [`synthesize`], reads this set after `walk`
/// returns regardless of whether it returned `Ok` or `Err`). Stops at the
/// first failure; does NOT itself destroy the pointer/manager or attempt any
/// cleanup — that is entirely [`synthesize`]'s single exit-point job, so it
/// happens exactly once no matter which [`Step`] (if any) failed.
fn walk(
    pointer: &ZwlrVirtualPointerV1,
    conn: &Connection,
    seq: &Seq,
    pressed: &mut HashSet<u32>,
) -> Result<(), PointerError> {
    for step in &seq.0 {
        match *step {
            Step::Motion { dx, dy } => {
                pointer.motion(now_ms(), dx as f64, dy as f64);
                pointer.frame();
            }
            Step::Button { code, pressed: down } => {
                let wl_state = if down { ButtonState::Pressed } else { ButtonState::Released };
                pointer.button(now_ms(), code, wl_state);
                if down {
                    pressed.insert(code);
                } else {
                    pressed.remove(&code);
                }
                pointer.frame();
            }
            Step::Wheel { axis, notches } => {
                if notches == 0 {
                    continue;
                }
                // Defense-in-depth (Phase B review nit 3): clamp here too,
                // regardless of whether the caller already did — see
                // MAX_WHEEL_NOTCHES_PER_STEP's own doc.
                let notches = notches.clamp(-MAX_WHEEL_NOTCHES_PER_STEP, MAX_WHEEL_NOTCHES_PER_STEP);
                let wl_axis = match axis {
                    Axis::Vertical => WlAxis::VerticalScroll,
                    Axis::Horizontal => WlAxis::HorizontalScroll,
                };
                let sign = if notches > 0 { 1.0 } else { -1.0 };
                let discrete_sign: i32 = if notches > 0 { 1 } else { -1 };
                // One frame PER NOTCH (B1): wl_pointer allows at most one
                // axis_discrete per axis per frame, and axis_source is
                // per-frame state, so it's resent every notch too.
                for _ in 0..notches.unsigned_abs() {
                    let t = now_ms();
                    pointer.axis_source(WlAxisSource::Wheel);
                    pointer.axis(t, wl_axis, sign * WHEEL_VALUE);
                    pointer.axis_discrete(t, wl_axis, sign * WHEEL_VALUE, discrete_sign);
                    pointer.frame();
                }
            }
            Step::Pause { ms } => {
                // Flush before sleeping — nothing queued so far should sit
                // buffered while this thread blocks.
                flush_retrying(conn)?;
                std::thread::sleep(Duration::from_millis(ms));
                continue; // already flushed; skip the flush below.
            }
        }
        flush_retrying(conn)?;
    }
    Ok(())
}

// synthesize() itself is NOT unit-tested here — it opens a real Wayland
// socket (see the module header). No #[cfg(test)] mod in this file; the
// Axis/Step/Seq/PointerError shapes it operates on are exercised entirely
// through the pure builders that assemble them, in `point.rs`'s own test
// module.
