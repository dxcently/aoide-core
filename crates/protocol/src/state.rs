//! The canonical session-state fold (pure).

/// The canonical session-state vocabulary the desktop renders VERBATIM — no
/// widget-side regex derivation (that split-brain is what this replaces). Every
/// producer (hooks, `conduct`, the reaper) writes one of these onto
/// `sessions.json`; this shim also folds the legacy / hook-phase vocab
/// (`running`/`waiting`/`blocked`) onto it, so an old record is migrated the
/// first time any writer touches the file — no rollout dance.
///
///   working  — in a turn / running a tool (or a shell running a foreground cmd)
///   awaiting — needs the user (a permission prompt or the idle-input ping); the
///              dock peeks on this and only this (`needsInput ⇔ awaiting`)
///   stopped  — the turn ENDED and the agent is sitting at the prompt, RECENTLY.
///              Alive and warm: the natural face of a session you just finished
///              talking to. Ages out to `idle` after
///              [`crate::reap::STOPPED_IDLE_AFTER_SECS`] in the reaper pass.
///   idle     — at rest and COLD: stopped for more than an hour, or freshly
///              created / resumed and not yet active (a bare shell prompt too)
///   done     — the session ENDED (SessionEnd / a reap). Never `stopped`.
///
/// `stop`/`stopped` map to `stopped`, NOT `done`: the only producer that ever
/// writes either token is a Stop-hook adapter (`graph session phase --phase
/// stop`, the shape `entities/Agent-Hooking` documents for a foreign harness),
/// and the Stop hook means "the turn ended", not "the process exited". Real
/// termination arrives as `SessionEnd` (→ `do_session_end`, which writes `done`
/// directly and never routes through this shim) or as the explicit
/// `exit`/`finished`/`complete` vocabulary below.
pub fn canonical_state(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "working" | "running" | "active" | "busy" | "tool" | "trace" => "working",
        "awaiting" | "blocked" | "await" => "awaiting",
        "stopped" | "stop" => "stopped",
        "idle" | "waiting" | "ready" | "sleep" => "idle",
        "done" | "exit" | "finished" | "complete" => "done",
        // Empty/unknown → at rest (never invent a working/awaiting signal).
        _ => "idle",
    }
}
