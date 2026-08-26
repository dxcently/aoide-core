//! `screen info` / `screen shot` / `screen point <command>` — thin
//! registrations over this crate's domain modules (Phase 1: info/shot;
//! Phase 2: the six `screen point` commands; Phase B of the pointer-emulation
//! workstream, the User 2026-08-17, adds `drag`/`hover` and extends `click`
//! --count and `scroll` to two axes, for eight `screen point` commands total;
//! Phase E, same day, adds `screen diff`; Phase F, same day, adds
//! `screen point text`, for nine `screen point` commands total). Handler
//! bodies live in `crate::hypr`/`crate::capture`/`crate::point`/
//! `crate::diff`/`crate::text`; this module only wires schema metadata to
//! them — nothing here duplicates screen-domain logic (mirrors
//! `aoide-conduct`'s `commands/graph.rs`'s own split of commands from logic).
//! Moved out of `aoide-conduct`'s `commands/screen.rs` at P-A1 of the
//! binary-split workstream — same file, new crate root, `crate::screen::X`
//! handler paths flattened to `crate::X` since this crate's domain modules
//! now live at the crate root instead of under a `screen` submodule.

use aoide_protocol::registry::{arg, cmd, flag, Registry};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["screen", "info"],
        summary: "Read-only desktop readout for agents: monitors (+ usable region after reserve), cursor position, active workspace, its mapped clients, and every layer surface (the \"is a popup open\" signal). Source: typed hyprctl -j parses.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::info,
    ));
    r.insert(cmd!(
        path: ["screen", "shot"],
        summary: "Capture the screen via grim: full layout by default, one monitor (--output), an explicit rectangle (--region), a human-picked region (--pick), a specific Hyprland window (--window), or a conducted agent-session's window (--session). Out-of-bounds regions are clamped to the hyprctl-reported layout and the outcome says so. Writes a JSON sidecar next to every capture — the sidecar also carries a full desktop snapshot (cursor + every mapped client/layer surface), so a caller rarely needs a follow-up `screen info` just to know what else was on screen. Coordinates read off the image (an OCR word, a click target picked by eye) invert back to screen space via that same sidecar's origin/scale — see `screen point`'s `--from-shot`.",
        args: [],
        flags: [
            flag!("output", "string", "Capture exactly this monitor's rect (mutually exclusive with --region/--pick/--window/--session)."),
            flag!("region", "string", "Capture this rectangle, \"X,Y WxH\" (mutually exclusive with --output/--pick/--window/--session)."),
            flag!("pick", "bool", "Human-attended region pick via slurp (mutually exclusive with --output/--region/--window/--session)."),
            flag!("session", "string", "Capture a conducted agent-session's window by session id (resolved via its windowAddress, falling back to its pid; mutually exclusive with --output/--region/--pick/--window)."),
            flag!("window", "string", "Capture exactly this Hyprland window by address, as reported by `screen info`/`hyprctl clients` (mutually exclusive with --output/--region/--pick/--session)."),
            flag!("format", "string", "png | jpeg (default png — lossless, smaller for flat UI, best input for the OCR phase; pass jpeg for photographic/wallpaper-heavy captures)."),
            flag!("quality", "string", "JPEG quality 0-100 (default 80; ignored for png)."),
            flag!("scale", "string", "Output scale factor, e.g. 0.5 or 2 (default 1 — exactly 1:1 with the screen; mutually exclusive with --fit)."),
            flag!("fit", "string", "Downscale to fit inside WxH (e.g. 1280x800), never upscaling — a model-friendly frame with an exact scale factor recorded in the sidecar for --from-shot to invert (mutually exclusive with --scale)."),
            flag!("cursor", "bool", "Draw the composited cursor into the capture (grim -c). Off by default: a drawn cursor registers as a pixel change to the screen-diff command even on a pure pointer move."),
            flag!("out", "string", "Explicit destination path (else auto-named under the captures dir)."),
            flag!("comment", "string", "Free-text note stored in the capture's sidecar."),
        ],
        gated: false,
        implemented: true,
        handler: crate::shot,
    ));

    // ── Phase 2: `screen point <command>` — pointer synthesis via a native
    // zwlr_virtual_pointer_v1 client (`screen::point`/`screen::synth`, the
    // latter added Phase A of the pointer-emulation workstream, replacing
    // an earlier wlrctl shell-out with the same on-wire behavior). See
    // those modules' headers for the full design; nine commands total (Phase B
    // added `drag`/`hover`; Phase F added `text`) — seven
    // (move/click/drag/hover/scroll/restore/text) touch the
    // pointer-synthesis boundary or dispatch a warp and are NOT proven live
    // against the real pointer this phase (HARD RULE 5); `idle`/`save` are
    // read-only and ARE live-proven.

    r.insert(cmd!(
        path: ["screen", "point", "move"],
        summary: "Absolute pointer move: read the current cursor via hyprctl, emit the delta as a real virtual-pointer motion event (native zwlr_virtual_pointer_v1; unlike a warp, this fires hover/motion inside surfaces the pointer already entered), then verify it landed exactly on target. Exits nonzero on drift (a human moved the mouse, or the target is off-screen) rather than sailing on to a blind click.",
        args: [
            arg!("x", "string", true, "Target X, Hyprland logical px (may be negative on a multi-monitor layout) — or IMAGE px when --from-shot is given."),
            arg!("y", "string", true, "Target Y."),
        ],
        flags: [
            flag!("from-shot", "string", "Path to a `screen shot` capture: interpret x/y as IMAGE pixels off that capture's sidecar (origin/scale) and convert to screen space before moving."),
        ],
        gated: false,
        implemented: true,
        handler: crate::point_move,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "click"],
        // The "1-10" below mirrors point::MAX_CLICK_COUNT — `summary` is
        // `&'static str`, so the const can't be embedded directly; update
        // both if that bound ever changes (same cross-reference discipline
        // as `scroll`'s "+/-100" below, Phase A review nit 2/Phase B).
        summary: "Synthesize a button press via a native virtual-pointer client. Optional x y acts as a pre-flight guard: refuses the press (nonzero exit) unless the pointer is EXACTLY there — the one irreversible action gets the one guard. --count repeats the click 1-10 times (60ms between clicks).",
        args: [
            arg!("button", "string", false, "left | right | middle (default left)."),
            arg!("x", "string", false, "Guard X — refuse unless the pointer is exactly here (requires y too). IMAGE px when --from-shot is given."),
            arg!("y", "string", false, "Guard Y (requires x too)."),
        ],
        flags: [
            flag!("count", "string", "Number of clicks, 1-10 (default 1)."),
            flag!("from-shot", "string", "Path to a `screen shot` capture: interpret the x/y guard as IMAGE pixels off that capture's sidecar (origin/scale) and convert to screen space before guarding."),
        ],
        gated: false,
        implemented: true,
        handler: crate::point_click,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "drag"],
        // The "1-200" below mirrors point::DRAG_MIN_STEPS..=DRAG_MAX_STEPS —
        // same cross-reference discipline as `scroll`'s "+/-100" below
        // (`summary` is `&'static str`, can't embed the consts directly).
        summary: "Press-move-release as one atomic sequence via the native virtual-pointer boundary (press and release never split across separate synthesize() calls — the stuck-button safety contract). Refuses if either endpoint is off the layout before pressing anything. Moves to (x1,y1) first, verified exactly like `move`, and refuses WITHOUT pressing on drift; presses, interpolates --steps relative motion events to (x2,y2), then releases; verifies the release landed on target and reports drift after release as \"button not stuck, already released\".",
        args: [
            arg!("x1", "string", true, "Start X, Hyprland logical px (may be negative on a multi-monitor layout) — or IMAGE px when --from-shot is given."),
            arg!("y1", "string", true, "Start Y."),
            arg!("x2", "string", true, "End X."),
            arg!("y2", "string", true, "End Y."),
        ],
        flags: [
            flag!("button", "string", "left | right | middle (default left)."),
            flag!("steps", "string", "Interpolated motion steps between start and end, 1-200 (default 20)."),
            flag!("from-shot", "string", "Path to a `screen shot` capture: interpret BOTH endpoints as IMAGE pixels off that capture's sidecar (origin/scale) and convert to screen space before dragging."),
        ],
        gated: false,
        implemented: true,
        handler: crate::point_drag,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "hover"],
        // The "1-10000" below mirrors
        // point::HOVER_MIN_SETTLE_MS..=HOVER_MAX_SETTLE_MS — same
        // cross-reference discipline as `scroll`'s "+/-100" below
        // (`summary` is `&'static str`, can't embed the consts directly).
        summary: "Move to (x,y) via the same move+verify path as `move`, hold for --settle-ms, then report what the desktop's layer surfaces and windows did while parked there (appeared/disappeared/retitled, snapshotted via hyprctl before and after) — a tooltip or menu opening IS a new layer surface, so this delta is the command's whole purpose.",
        args: [
            arg!("x", "string", true, "Target X, Hyprland logical px (may be negative on a multi-monitor layout) — or IMAGE px when --from-shot is given."),
            arg!("y", "string", true, "Target Y."),
        ],
        flags: [
            flag!("settle-ms", "string", "Milliseconds to hold before re-reading the desktop, 1-10000 (default 500)."),
            flag!("from-shot", "string", "Path to a `screen shot` capture: interpret x/y as IMAGE pixels off that capture's sidecar (origin/scale) and convert to screen space before moving."),
        ],
        gated: false,
        implemented: true,
        handler: crate::point_hover,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "scroll"],
        // The "+/-100" below mirrors point::MAX_SCROLL_NOTCHES (itself
        // DEFINED as synth::MAX_WHEEL_NOTCHES_PER_STEP) — update this prose
        // if that bound ever changes (Phase A review nit 2, folded in Phase
        // B). `summary` is `&'static str`, so the const can't be embedded
        // directly; this comment is the cross-reference instead.
        summary: "Scroll wheel events via a native virtual-pointer client. Positive dy scrolls down, negative up (one notch = one real wheel detent, matching a physical wheel pulled toward the user); optional dx scrolls right (positive) or left (negative). Both axes are clamped to +/-100 notches per call; a clamp is announced in the outcome.",
        args: [
            arg!("dy", "string", true, "Vertical notches: positive = down, negative = up."),
            arg!("dx", "string", false, "Horizontal notches: positive = right, negative = left (default 0)."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::point_scroll,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "idle"],
        summary: "Block (polling hyprctl cursorpos every 250ms) until N consecutive identical samples are seen, or timeout (seconds) elapses — a human's hand tremor breaks the streak, so this is a genuine \"nobody is touching the mouse\" gate. Read-only; never touches the pointer-synthesis boundary.",
        args: [
            arg!("samples", "string", false, "Consecutive identical samples required (default 10)."),
            arg!("timeout", "string", false, "Give up after this many seconds (default 60)."),
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::point_idle,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "save"],
        summary: "Persist the current cursor position to state (read-only cursor sample; the position is restored later via `screen point restore`).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::point_save,
    ));
    r.insert(cmd!(
        path: ["screen", "point", "restore"],
        summary: "Warp the cursor back to the position last saved by `screen point save` (hyprctl dispatch movecursor — a warp is fine here: it's returning to a known spot, not synthesizing a human gesture).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: crate::point_restore,
    ));

    // ── Phase F of the pointer-emulation workstream: `screen point text
    // <text>` — click a word/phrase `screen ocr` already located, by NAME
    // instead of a picked-by-eye pixel (`screen::text`). `--from-shot` is
    // REQUIRED here and means something DIFFERENT than on move/click/drag/
    // hover: it names the OCR SOURCE, never a coordinate space to convert —
    // `screen ocr`'s word bboxes are already absolute screen coordinates, so
    // no transform runs (see that module's own header on the double-
    // transform bug this avoids).

    r.insert(cmd!(
        path: ["screen", "point", "text"],
        summary: "Click a word or phrase an earlier `screen ocr` pass located: matches <text> case-insensitively against that capture's OCR words (a multi-word phrase must be consecutive words on the same visual line), then moves to the match's centre (verified, drift refuses) and fires a guarded click there. Zero matches errors; more than one requires --nth to disambiguate. --dry-run resolves the match and reports its centre with no pointer motion at all — safe to run live. NOTE: --from-shot here selects the OCR SOURCE, not a coordinate space to convert — OCR word bboxes are already absolute screen coordinates.",
        args: [
            arg!("text", "string", true, "The word or phrase to find among the capture's OCR words (case-insensitive; quote a multi-word phrase as one argument — trailing unquoted words are refused, not silently dropped). OCR words carry whatever punctuation tesseract attached, e.g. \"Save:\" won't match a search for \"Save\" — if a word you can see isn't matching, check the capture's OCR text for stray punctuation."),
        ],
        flags: [
            flag!("from-shot", "string", "REQUIRED. Path to a `screen shot` capture that has already been OCR'd (`screen ocr <capture>`) — the sidecar's ocr.words are the only source of text this command searches."),
            flag!("nth", "string", "1-based: which match to act on when more than one is found (ordered top-left-first, top row then left-to-right)."),
            flag!("button", "string", "left | right | middle (default left)."),
            flag!("dry-run", "bool", "Resolve the match and report its centre only — no pointer motion at all."),
        ],
        gated: false,
        implemented: true,
        handler: crate::point_text,
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
        handler: crate::ocr,
    ));

    // ── Phase E of the pointer-emulation workstream: `screen diff
    // <before-capture>` — mechanical act-verification (`screen::diff`).
    // Re-shoots the before-capture's identical rect/scale/format/quality,
    // pixel-diffs the two images, and reports a hyprctl inventory delta
    // alongside it. "Nothing changed" is success, not an error — see that
    // module's header.

    r.insert(cmd!(
        path: ["screen", "diff"],
        summary: "Mechanical act-verification: re-shoot a `screen shot` capture's identical rect/scale/format/quality after an optional settle delay, pixel-diff the two images (any RGB channel's delta over --threshold counts; alpha ignored), and report a changed-pixel bounding box (screen AND image coordinates) plus a hyprctl inventory delta (windows/layers appeared/disappeared/retitled). \"Nothing changed\" is a normal, present-tense success — not an error a caller has to catch. The same result object is written into the after-capture's own sidecar `diff` field.",
        args: [
            arg!("before-capture", "string", true, "Path to an existing `screen shot` capture (must have a sidecar `<name>.json` next to it — origin/scale/size/format/quality are all recovered from there, never re-asked)."),
        ],
        flags: [
            flag!("settle-ms", "string", "Milliseconds to wait before the after-shot, 0-60000 (default 250; 0 means \"diff right now\")."),
            flag!("threshold", "string", "Per-channel absolute delta (0-255) above which a pixel counts as changed (default 8 — absorbs JPEG noise/subpixel AA)."),
            flag!("out", "string", "Explicit destination path for the after-image (else auto-named under the captures dir, like `screen shot`)."),
        ],
        gated: false,
        implemented: true,
        handler: crate::diff,
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
        handler: crate::send,
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
            "output", "region", "pick", "session", "window", "format", "quality", "scale", "fit",
            "cursor", "out", "comment", "json",
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

    // ── Phase 2: screen point <command>; extended Phase B (drag/hover added,
    // six → eight), Phase F (text added, eight → nine) ──────────────────────

    #[test]
    fn all_nine_point_commands_are_registered_and_implemented_with_json() {
        let mut r = Registry::new();
        register(&mut r);
        for command in ["move", "click", "scroll", "idle", "save", "restore", "drag", "hover", "text"] {
            let c = r
                .get(&["screen".to_string(), "point".to_string(), command.to_string()])
                .unwrap_or_else(|| panic!("screen point {command} not registered"));
            assert!(c.implemented, "screen point {command} not marked implemented");
            assert!(
                c.flags.iter().any(|f| f.name == "json"),
                "screen point {command} missing --json"
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
        assert_eq!(sc.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["dy", "dx"]);
        assert!(sc.args[0].required, "dy is required");
        assert!(!sc.args[1].required, "dx is optional (defaults to 0)");
    }

    #[test]
    fn drag_declares_four_required_positional_args_and_its_flags() {
        let mut r = Registry::new();
        register(&mut r);
        let dr = r.get(&["screen".to_string(), "point".to_string(), "drag".to_string()]).unwrap();
        assert_eq!(
            dr.args.iter().map(|a| a.name).collect::<Vec<_>>(),
            vec!["x1", "y1", "x2", "y2"]
        );
        assert!(dr.args.iter().all(|a| a.required), "drag's four coordinates are all required");
        for name in ["button", "steps", "from-shot", "json"] {
            assert!(dr.flags.iter().any(|f| f.name == name), "drag missing --{name}");
        }
    }

    #[test]
    fn hover_declares_its_required_positional_args_and_flags() {
        let mut r = Registry::new();
        register(&mut r);
        let hv = r.get(&["screen".to_string(), "point".to_string(), "hover".to_string()]).unwrap();
        assert_eq!(hv.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["x", "y"]);
        assert!(hv.args.iter().all(|a| a.required), "hover's x/y are both required");
        for name in ["settle-ms", "from-shot", "json"] {
            assert!(hv.flags.iter().any(|f| f.name == name), "hover missing --{name}");
        }
    }

    #[test]
    fn click_declares_a_count_flag() {
        let mut r = Registry::new();
        register(&mut r);
        let cl = r.get(&["screen".to_string(), "point".to_string(), "click".to_string()]).unwrap();
        assert!(cl.flags.iter().any(|f| f.name == "count"), "click missing --count");
        assert!(cl.flags.iter().any(|f| f.name == "from-shot"), "click missing --from-shot");
    }

    // ── Phase F: screen point text ───────────────────────────────────────

    #[test]
    fn text_declares_its_required_positional_arg_and_flags() {
        let mut r = Registry::new();
        register(&mut r);
        let tx = r.get(&["screen".to_string(), "point".to_string(), "text".to_string()]).unwrap();
        assert_eq!(tx.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["text"]);
        assert!(tx.args[0].required, "text's <text> arg is required");
        for name in ["from-shot", "nth", "button", "dry-run", "json"] {
            assert!(tx.flags.iter().any(|f| f.name == name), "text missing --{name}");
        }
    }

    // ── Phase D: --from-shot on move/click/drag/hover ───────────────────

    #[test]
    fn move_declares_a_from_shot_flag() {
        let mut r = Registry::new();
        register(&mut r);
        let mv = r.get(&["screen".to_string(), "point".to_string(), "move".to_string()]).unwrap();
        assert!(mv.flags.iter().any(|f| f.name == "from-shot"), "move missing --from-shot");
    }

    #[test]
    fn scroll_idle_save_restore_do_not_declare_a_from_shot_flag() {
        // --from-shot only makes sense where a command takes coordinate args —
        // scroll/idle/save/restore don't, and shouldn't advertise it.
        let mut r = Registry::new();
        register(&mut r);
        for command in ["scroll", "idle", "save", "restore"] {
            let c = r.get(&["screen".to_string(), "point".to_string(), command.to_string()]).unwrap();
            assert!(
                !c.flags.iter().any(|f| f.name == "from-shot"),
                "screen point {command} should not declare --from-shot"
            );
        }
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

    // ── Phase E: screen diff ─────────────────────────────────────────────

    #[test]
    fn screen_diff_is_registered_implemented_with_json_and_the_expected_shape() {
        let mut r = Registry::new();
        register(&mut r);
        let c = r.get(&["screen".to_string(), "diff".to_string()]).unwrap();
        assert!(c.implemented);
        assert!(c.flags.iter().any(|f| f.name == "json"));
        assert_eq!(c.args.iter().map(|a| a.name).collect::<Vec<_>>(), vec!["before-capture"]);
        assert!(c.args[0].required, "the before-capture path is required, not optional");
        for name in ["settle-ms", "threshold", "out"] {
            assert!(c.flags.iter().any(|f| f.name == name), "missing --{name}");
        }
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
