//! `screen info` / `screen shot` / `screen point <verb>` — thin
//! registrations over this crate's `screen/` domain (Phase 1: info/shot;
//! Phase 2: the six `screen point` verbs). Handler bodies live in
//! `screen::hypr`/`screen::capture`/`screen::point`; this module only wires
//! schema metadata to them — nothing here duplicates screen-domain logic
//! (mirrors `commands/graph.rs`'s own split of verbs from logic).

use aoide_protocol::registry::{arg, cmd, flag, Registry};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["screen", "info"],
        summary: "Read-only desktop readout for agents: monitors (+ usable region after reserve), cursor position, active workspace, its mapped clients, and every layer surface (the \"is a popup open\" signal). Source: typed hyprctl -j parses.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::info,
    ));
    r.insert(cmd!(
        path: ["screen", "shot"],
        summary: "Capture the screen via grim: full layout by default, one monitor (--output), an explicit rectangle (--region), a human-picked region (--pick), a specific Hyprland window (--window), or a conducted agent-session's window (--session). Out-of-bounds regions are clamped to the hyprctl-reported layout and the outcome says so. Writes a JSON sidecar next to every capture.",
        args: [],
        flags: [
            flag!("output", "string", "Capture exactly this monitor's rect (mutually exclusive with --region/--pick/--window/--session)."),
            flag!("region", "string", "Capture this rectangle, \"X,Y WxH\" (mutually exclusive with --output/--pick/--window/--session)."),
            flag!("pick", "bool", "Human-attended region pick via slurp (mutually exclusive with --output/--region/--window/--session)."),
            flag!("session", "string", "Capture a conducted agent-session's window by session id (resolved via its windowAddress, falling back to its pid; mutually exclusive with --output/--region/--pick/--window)."),
            flag!("window", "string", "Capture exactly this Hyprland window by address, as reported by `screen info`/`hyprctl clients` (mutually exclusive with --output/--region/--pick/--session)."),
            flag!("format", "string", "png | jpeg (default png — lossless, smaller for flat UI, best input for the OCR phase; pass jpeg for photographic/wallpaper-heavy captures)."),
            flag!("quality", "string", "JPEG quality 0-100 (default 80; ignored for png)."),
            flag!("scale", "string", "Output scale factor, e.g. 0.5 or 2 (default 1 — exactly 1:1 with the screen)."),
            flag!("out", "string", "Explicit destination path (else auto-named under the captures dir)."),
            flag!("comment", "string", "Free-text note stored in the capture's sidecar."),
        ],
        gated: false,
        implemented: true,
        handler: crate::screen::shot,
    ));

    // ── Phase 2: `screen point <verb>` — pointer synthesis via wlrctl
    // (`screen::point`). See that module's header for the full design;
    // none of the six are proven live against the real pointer this phase
    // (HARD RULE 5) — `idle`/`save` are read-only and ARE live-proven.

    r.insert(cmd!(
        path: ["screen", "point", "move"],
        summary: "Absolute pointer move: read the current cursor via hyprctl, emit the delta as a real wlrctl virtual-pointer motion event (unlike a warp, this fires hover/motion inside surfaces the pointer already entered), then verify it landed exactly on target. Exits nonzero on drift (a human moved the mouse, or the target is off-screen) rather than sailing on to a blind click.",
        args: [
            arg!("x", "string", true, "Target X, Hyprland logical px (may be negative on a multi-monitor layout)."),
            arg!("y", "string", true, "Target Y."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::point_move,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "click"],
        summary: "Synthesize a button press via wlrctl. Optional x y acts as a pre-flight guard: refuses the press (nonzero exit) unless the pointer is EXACTLY there — the one irreversible action gets the one guard.",
        args: [
            arg!("button", "string", false, "left | right | middle (default left)."),
            arg!("x", "string", false, "Guard X — refuse unless the pointer is exactly here (requires y too)."),
            arg!("y", "string", false, "Guard Y (requires x too)."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::point_click,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "scroll"],
        summary: "Scroll wheel events via wlrctl. Positive n scrolls down (one notch = wlrctl value 5, matching a physical wheel pulled toward the user); negative scrolls up.",
        args: [
            arg!("n", "string", true, "Notches: positive = down, negative = up."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::point_scroll,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "idle"],
        summary: "Block (polling hyprctl cursorpos every 250ms) until N consecutive identical samples are seen, or timeout (seconds) elapses — a human's hand tremor breaks the streak, so this is a genuine \"nobody is touching the mouse\" gate. Read-only; never touches wlrctl.",
        args: [
            arg!("samples", "string", false, "Consecutive identical samples required (default 10)."),
            arg!("timeout", "string", false, "Give up after this many seconds (default 60)."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::point_idle,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "save"],
        summary: "Persist the current cursor position to state (read-only cursor sample; the position is restored later via `screen point restore`).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::point_save,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "restore"],
        summary: "Warp the cursor back to the position last saved by `screen point save` (hyprctl dispatch movecursor — a warp is fine here: it's returning to a known spot, not synthesizing a human gesture).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::point_restore,
    ));

    // ── Phase 3: `screen ocr <capture>` — tesseract text extraction over a
    // `screen shot` capture (`screen::ocr`). Writes into the capture's own
    // sidecar `ocr` field (present-and-null since phase 1).

    r.insert(cmd!(
        path: ["screen", "ocr"],
        summary: "OCR an existing `screen shot` capture via tesseract (TSV mode, PSM 11 sparse text): recover its text with per-word bounding boxes in ABSOLUTE SCREEN coordinates (image pixels converted via the capture's own sidecar origin/scale), then write the result into that sidecar's `ocr` field. Requires the capture to already have its `<name>.json` sidecar.",
        args: [
            arg!("capture", "string", true, "Path to an existing capture image (must have a sidecar `<name>.json` next to it, written by `screen shot`)."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::screen::ocr,
    ));

    // ── Phase 5: `screen send <capture>` — hand a capture (+ comment + OCR
    // text) to another agent (`screen::send`). The payoff of the family:
    // capture → ocr → SEND. Routes through the SAME two already-gated doors
    // `graph send`/`a2a agent send` use — see that module's header.

    r.insert(cmd!(
        path: ["screen", "send"],
        summary: "Hand a `screen shot` capture to another agent: compose a message from its absolute path plus a comment and OCR text (read from the sidecar, or overridden by --comment), then deliver it to a conducted session (--session, via the SAME held-pending-by-default gate `graph send` uses — --yes authorizes delivery) or a registered external A2A agent (--agent, via the SAME message/send driver `a2a agent send` uses — delivers immediately, no hold). --session and --agent are mutually exclusive; exactly one is required.",
        args: [
            arg!("capture", "string", true, "Path to an existing capture image (its sidecar `<name>.json`, if present, enriches the message with its stored comment and any OCR text)."),
        ],
        flags: [
            flag!("session", "string", "Deliver to this conducted session id (mutually exclusive with --agent; HELD pending approval unless --yes)."),
            flag!("agent", "string", "Deliver to this registered external A2A agent's name (mutually exclusive with --session; delivers immediately)."),
            flag!("comment", "string", "Override the sidecar's stored comment for this send."),
            flag!("yes", "bool", "Authorize delivery to a --session target now (irrelevant to --agent, which always delivers immediately)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::screen::send,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_screen_commands_are_registered_with_the_expected_flags() {
        let mut r = Registry::new();
        register(&mut r);
        let info = r.get(&["screen".to_string(), "info".to_string()]).unwrap();
        assert!(info.implemented);
        assert!(info.flags.iter().any(|f| f.name == "json"));

        let shot = r.get(&["screen".to_string(), "shot".to_string()]).unwrap();
        assert!(shot.implemented);
        for name in [
            "output", "region", "pick", "session", "window", "format", "quality", "scale", "out",
            "comment", "json",
        ] {
            assert!(shot.flags.iter().any(|f| f.name == name), "missing --{name}");
        }
    }

    #[test]
    #[should_panic(expected = "duplicate command path")]
    fn registering_twice_panics_on_duplicate_paths() {
        let mut r = Registry::new();
        register(&mut r);
        register(&mut r);
    }

    // ── Phase 2: screen point <verb> ─────────────────────────────────────

    #[test]
    fn all_six_point_verbs_are_registered_and_implemented_with_json() {
        let mut r = Registry::new();
        register(&mut r);
        for verb in ["move", "click", "scroll", "idle", "save", "restore"] {
            let c = r
                .get(&["screen".to_string(), "point".to_string(), verb.to_string()])
                .unwrap_or_else(|| panic!("screen point {verb} not registered"));
            assert!(c.implemented, "screen point {verb} not marked implemented");
            assert!(
                c.flags.iter().any(|f| f.name == "json"),
                "screen point {verb} missing --json"
            );
        }
    }

    #[test]
    fn move_and_scroll_declare_their_required_positional_args() {
        let mut r = Registry::new();
        register(&mut r);

        let mv = r.get(&["screen".to_string(), "point".to_string(), "move".to_string()]).unwrap();
        let names: Vec<&str> = mv.args.iter().map(|a| a.name).collect();
        assert_eq!(names, vec!["x", "y"]);
        assert!(mv.args.iter().all(|a| a.required), "move's x/y are both required");

        let sc = r.get(&["screen".to_string(), "point".to_string(), "scroll".to_string()]).unwrap();
        assert_eq!(sc.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["n"]);
        assert!(sc.args[0].required);
    }

    #[test]
    fn click_idle_declare_their_args_optional() {
        let mut r = Registry::new();
        register(&mut r);

        let cl = r.get(&["screen".to_string(), "point".to_string(), "click".to_string()]).unwrap();
        assert_eq!(cl.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["button", "x", "y"]);
        assert!(cl.args.iter().all(|a| !a.required), "click's args are all optional — arity is enforced by the handler, not the schema");

        let idl = r.get(&["screen".to_string(), "point".to_string(), "idle".to_string()]).unwrap();
        assert_eq!(idl.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["samples", "timeout"]);
        assert!(idl.args.iter().all(|a| !a.required));
    }

    #[test]
    fn save_and_restore_take_no_positional_args() {
        let mut r = Registry::new();
        register(&mut r);
        let save = r.get(&["screen".to_string(), "point".to_string(), "save".to_string()]).unwrap();
        assert!(save.args.is_empty());
        let restore = r.get(&["screen".to_string(), "point".to_string(), "restore".to_string()]).unwrap();
        assert!(restore.args.is_empty());
    }

    // ── Phase 3: screen ocr ──────────────────────────────────────────────

    #[test]
    fn screen_ocr_is_registered_implemented_with_json_and_a_required_capture_arg() {
        let mut r = Registry::new();
        register(&mut r);
        let c = r.get(&["screen".to_string(), "ocr".to_string()]).unwrap();
        assert!(c.implemented);
        assert!(c.flags.iter().any(|f| f.name == "json"));
        assert_eq!(c.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["capture"]);
        assert!(c.args[0].required, "the capture path is required, not optional");
    }

    // ── Phase 5: screen send ─────────────────────────────────────────────

    #[test]
    fn screen_send_is_registered_implemented_with_json_and_the_expected_shape() {
        let mut r = Registry::new();
        register(&mut r);
        let c = r.get(&["screen".to_string(), "send".to_string()]).unwrap();
        assert!(c.implemented);
        assert!(c.flags.iter().any(|f| f.name == "json"));
        assert_eq!(c.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["capture"]);
        assert!(c.args[0].required, "the capture path is required, not optional");
        for name in ["session", "agent", "comment", "yes"] {
            assert!(c.flags.iter().any(|f| f.name == name), "missing --{name}");
        }
    }
}
