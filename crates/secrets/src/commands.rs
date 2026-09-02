//! `aoide secrets` — the secrets broker's CLI surface (Workstream SECRETS,
//! P-V2, P-V3, P-V4c, P-V4e, P-N1, P-N2, P-N3, P-G2). Registers SIXTEEN
//! commands:
//!
//! - `serve` — the long-running broker, special-cased at the entry point
//!   exactly like `a2a serve`/`conductor` (`cli`'s `run_cli`): this
//!   crate's handler only records the launch (or, on a non-`Cli` door,
//!   returns the "run it from a terminal" outcome); the accept loop itself
//!   (`crate::broker::serve`) is called from the special hook.
//! - `exec` — CLI-only, special-cased the SAME way. Spawns a child with
//!   inherited stdio and an injected env var — see `crate::client`'s
//!   module doc for why that can never go through the generic `Outcome`
//!   envelope (a value would have to ride through it).
//! - `enroll` (P-V3, `--show` added P-V4e) — CLI-only, special-cased the
//!   SAME way as `serve`/`exec`, for the same reason `exec` is: the printed
//!   `otpauth://` URI + base32 secret must never ride the `Outcome`
//!   envelope (this crate's `AGENTS.md`). [`handle_secrets_enroll`] only
//!   gates the door, rejects the `--force`/`--show` combination (a usage
//!   error — the two ask for opposite things: rotate vs. never touch), and
//!   records the launch; the actual secret generation/persistence/printing
//!   (`--force`/bare) or read-only reprint (`--show`) is `crate::enroll::
//!   run`/`crate::enroll::show`, dispatched from `cli`'s `special` hook —
//!   the SAME `if inv.path == ["secrets", "enroll"]` arm as before, not a
//!   second one (see that module's doc).
//! - `add`/`rm`/`grant`/`revoke` — the policy-CRUD admin quartet. Not
//!   special-cased (they only read/write `policy.json`, no socket, no
//!   value, ever, so they still run through the ordinary dispatch + audit
//!   path like any other command), but **CLI-only, door-gated the SAME way
//!   as `serve`/`exec`/`enroll`** (bounce-fix item 2, P-V2 review —
//!   [`require_cli`]): an earlier revision left them reachable over MCP/
//!   A2A/Daemon doors, which would let any agent already talking to aoide
//!   `secrets grant <secret> <itself>` and self-escalate. The gate returns
//!   the door-hint `Outcome` and returns BEFORE any `store::load_policies`/
//!   `store::save_policies` call, so a non-CLI invocation never mutates
//!   `policy.json`. `add`'s `--require-totp` flag (present since P-V2, live
//!   since P-V3's TOTP wiring) births the policy already gated — a secret
//!   never has to pass through an unrequired window before someone remembers
//!   to lock it down.
//! - `put` (P-V4c) — the write half: `secrets put <name>` reads the value
//!   from STDIN (never argv) and forwards it to the broker's `put` op over
//!   the socket. **NOT special-cased**, unlike `serve`/`exec`/`enroll`:
//!   [`handle_secrets_put`] is a PLAIN handler — CLI-only via the SAME
//!   [`require_cli`] gate as the admin quartet (an agent putting values is
//!   exactly what the design forbids), then it delegates the stdin-read +
//!   socket round trip to `crate::client::run_put`. This differs from
//!   `exec`/`enroll` in the one way that matters: `put`'s wire reply never
//!   carries a value (`{"ok":true,"replaced":bool}` or
//!   `{"ok":false,"error":...}` — P-67 below adds the `replaced`/`exists`
//!   fields, still no value either way), and its own success/failure
//!   message is name-only — so nothing about its return path ever needs to
//!   bypass the generic `Outcome` envelope the way a FETCHED value (`exec`)
//!   or a PRINTED secret (`enroll`) would. **P-V4e:** when stdin is a
//!   terminal, `crate::client::run_put` now prompts on STDERR and reads the
//!   value with terminal echo disabled instead of requiring a pipe — see
//!   that module's doc; a piped/redirected stdin is byte-identical to
//!   before. **P-67 ("warn before overwrite", this commit):** `put` gained
//!   a `--force` flag. Without it, overwriting a secret that already has a
//!   stored value is refused by the broker (`crate::broker::put_gate`'s
//!   `DeniedExists`); on a tty, `crate::client::run_put` turns that refusal
//!   into a `y/N` confirmation and, on yes, re-sends the SAME in-memory
//!   value with `overwrite: true` — the caller never retypes it. On a
//!   piped stdin there is no one to confirm with, so the refusal teaches
//!   `--force` instead. `--force` skips the confirmation entirely (works
//!   on a tty too) by sending `overwrite: true` on the very first attempt.
//!   [`handle_secrets_put`]'s own job barely changes: it reads the new
//!   `force` flag and passes it through to `run_put`, and reports the
//!   message `run_put` returns ("stored" vs. "replaced") instead of a
//!   fixed string, so the human (and the audit trail, via `broker::
//!   audit_put`'s new `replaced` field) sees which one happened.
//! - `set-totp` (P-V4e) — `secrets set-totp <name> on|off`: flips an
//!   EXISTING policy's `requireTotp` bit without hand-editing `policy.json`.
//!   Same `require_cli` gate as the rest of the admin surface; unknown name
//!   is a clean error; re-setting the same state is idempotent and reports
//!   "unchanged" honestly (house rule: report exactly what changed) rather
//!   than calling `.changed(...)` on a no-op write. Appended newest in
//!   `register()` before P-N1 (golden discipline — `pkgs/aoide/crates/
//!   AGENTS.md`: append, never reorder), golden 60 -> 61.
//! - `automate` (P-N1) — `secrets automate <name> on|off` flips the
//!   policy's new `automation.enabled` bit; `secrets automate <name>
//!   grant|revoke <consumer>` edits `automation.consumers` (the consumer
//!   name checked with the SAME [`valid_secret_name`] validation as every
//!   other name in this crate). Same `require_cli` + `require_admin_identity`
//!   gate as the rest of the admin surface; idempotent both ways — flipping
//!   to the state it already has, or granting/revoking a consumer already
//!   in/out of the list, reports "unchanged" and writes nothing (house rule
//!   2, `set-totp`'s own precedent). See `crate::policy::Automation`/
//!   `totp_required` for what this field actually gates:
//!   `broker::resolve_gate` skips the TOTP check ONLY for a consumer LISTED
//!   here while `enabled` is `true` — every other caller is unaffected.
//! - `expose` (P-N1) — `secrets expose <name> on|off` flips the policy's
//!   new `remote` bit. Same admin gate, same idempotency discipline as
//!   `automate`/`set-totp`. **NO behavior change today** — no non-local
//!   entry point exists yet — this command only lets an operator PRE-DECLARE a
//!   secret as remote-reachable ahead of one landing; see
//!   `crate::policy::Policy::remote`'s own doc and this crate's `AGENTS.md`
//!   for the invariant a future non-local door must hold.
//! - `allow-remote-origin` (LANE IDENTITY P-ID4) — `secrets
//!   allow-remote-origin <name> on|off` flips the policy's
//!   `allowRemoteOrigin` bit, the remote-ORIGIN admission axis
//!   `broker::resolve_gate`'s origin gate enforces LIVE (unlike `expose`,
//!   this one changes behavior the moment it flips): off (the default)
//!   refuses a resolve whose caller session is positively attested as
//!   remote-origin (sealed `peer:*`), on admits it. Same admin gate, same
//!   idempotency discipline as `expose`; the three axes' split is stated
//!   in `crate::policy::Policy::allow_remote_origin`'s own doc.
//! - `pending`/`approve`/`dismiss` (P-N2) — the parked-resolve completion
//!   surface: [`handle_secrets_pending`] lists every in-flight ask ([`crate::
//!   client::pending`], value-free by construction); [`handle_secrets_approve`]
//!   validates a TOTP code and releases the value down the ORIGINAL parked
//!   connection ([`crate::client::approve`] — its own reply never carries
//!   the value, `broker::handle_approve`'s doc); [`handle_secrets_dismiss`]
//!   refuses a parked ask outright ([`crate::client::dismiss`]). All three
//!   are **operator-side over the socket, same as `put`/`exec`** — CLI-only
//!   via [`require_cli`], but deliberately NOT gated by
//!   [`require_admin_identity`]: they never touch `policy.json`, only the
//!   broker's in-memory [`crate::park::ParkRegistry`] over the wire.
//!
//! `automate`/`expose` are appended in `register()` (golden discipline —
//! `pkgs/aoide/crates/AGENTS.md`: append, never reorder), golden 61 -> 63;
//! `pending`/`approve`/`dismiss` (P-N2) are appended last, golden 63 -> 66;
//! `watch` (tracker #71 Part 1 — the terminal completion
//! surface for a parked ask) is appended next, golden 66 -> 67;
//! `allow-remote-origin` (LANE IDENTITY P-ID4) is appended newest,
//! golden 81 -> 82 (the count moved between those landings for reasons
//! outside this crate — `crates/cli/src/registry.rs`'s own golden note is
//! the full chain).
//! - `watch` — a foreground, line-mode broker-event narrator + prompt
//!   surface (`crate::watch`'s own module doc has the full mechanism).
//!   [`handle_secrets_watch`] only gates the door (CLI-only, same
//!   [`require_cli`] as `pending`/`approve`/`dismiss` — no admin-identity
//!   check, same reasoning), refuses `--popup`+`--json` together as a usage
//!   error (tracker #71 Part 2, this commit — the `--popup` flag is
//!   registered on this same `cmd!` entry), and records the launch; the
//!   blocking loop itself (`crate::watch::run`) is special-cased from
//!   `cli`'s `special` hook the SAME way `serve`/`exec`/`enroll` already
//!   are.
//! - `migrate` (P-G2, task #72) — `secrets migrate <name> [--backend
//!   <target>]`: moves an EXISTING secret's stored VALUE from its policy's
//!   current backend to a target backend (default `age`) and flips the
//!   policy row. Admin command, DIRECT-HOME — same `require_cli` +
//!   `require_admin_identity` gate as `add`/`rm`/`grant`, never the
//!   socket. See [`handle_secrets_migrate`]'s own doc and `README.md`'s
//!   "Migrating a secret between backends" for the full ordering/removal
//!   rules. Appended newest, golden 67 -> 68.
//!
//! `add`/`rm`/`grant`/`revoke`/`enroll` run AS THE SECRETS USER in deployment
//! (`sudo -u aoide-secrets ...`, wrapped by the nix module at P-V4), but the
//! code itself is uid-agnostic — it only reads/writes whatever
//! `home::secrets_home()` resolves to, same as every other function here.
//! `add` reads NO value at any point: the secrets broker never stores one, only a
//! policy (backend name + key) pointing at where a value can be fetched
//! from later. `put` is the one command here whose stdin DOES carry a value —
//! it never touches this crate's own storage directly, only the broker's
//! `set` backend template, over the socket (`crate::broker::handle_put`'s
//! module doc).
//!
//! **`add`/`rm`/`grant`/`revoke`/`set-totp`/`automate`/`expose`/
//! `allow-remote-origin`/`migrate`
//! also carry the admin-identity guard** ([`require_admin_identity`], `home::admin_identity_check`'s
//! module doc — the yomi-strix incident, 2026-08-22): called right after
//! [`require_cli`] in every one of those handlers, BEFORE
//! `store::load_policies`/`store::save_policies` ever runs, it refuses the
//! call outright when this process's effective uid doesn't own the
//! secrets home — plain `sudo` (root, euid 0) is explicitly one of the
//! refused cases, not a bypass, because root CAN write regardless of
//! ownership, which is exactly what silently reowned `policy.json` to
//! `root:root` and bricked the broker (and every later admin command,
//! including the correctly-spelled `sudo -u aoide-secrets` retry) in the
//! field. `enroll`'s own write path (`enroll::run`) carries the same guard
//! directly, since its actual work happens in `cli`'s `special` hook, not
//! here — `enroll::show` (read-only, rotates nothing) does NOT carry it,
//! and neither does `put`/`exec`: those are the socket-side operator commands
//! this guard was never meant to cover (`home.rs`'s module doc).

use crate::home;
use crate::policy::valid_secret_name;
use aoide_protocol::output::Outcome;
use aoide_protocol::registry::{arg, cmd, flag, Registry};
use aoide_protocol::{Door, Invocation};
use serde_json::json;

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["secrets", "serve"],
        summary: "Run the secrets broker: a unix-socket JSON-lines server that resolves secrets by policy (Workstream SECRETS). Long-running, launched at the entry point like `a2a serve` — this record is the launch's audit line.",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_serve,
        examples: ["secrets serve"],
    ));
    r.insert(cmd!(
        path: ["secrets", "exec"],
        summary: "Resolve a secret and exec a command with it injected as an env var (Stdio::inherit throughout — never argv, never logged, never an Outcome/JSON field). CLI-only: the value would otherwise have to cross a door that isn't this process's own stdio.",
        args: [arg!("command", "string", true, "The command to exec with the secret injected — put it after `--` so its own flags pass through verbatim (the same declaration `conduct` carries for its wrapped command; an undeclared tail would trip the parser's zero-arg overflow guard).")],
        flags: [
            flag!("as", "string", "The consumer name to present to the broker (self-asserted — the policy's consumers[] list is the real gate, not caller identity)."),
            flag!("secret", "string", "The secret's policy name, optionally `name:VAR` to name the injected env var explicitly (default: the name, uppercased, `-` -> `_`)."),
            flag!("totp", "string", "A TOTP code for a requireTotp-gated secret — verified live against this host's enrolled secret (±1-timestep window, single-use: a wrong or already-used code is a plain denial). Omitted (or wrong) on a requireTotp secret PARKS the resolve instead of refusing outright — complete it with `secrets pending`/`secrets approve <id> --totp <code>` from another terminal, or wait out the timeout. Unresolvable only when no TOTP enrollment exists yet on this host (`secrets enroll`)."),
            flag!("reason", "string", "Free-text context for a popup/prompt surface to show alongside a parked ask -- what this ask is FOR, never a value. Defaults to the wrapped command's own argv, space-joined and truncated to ~60 chars, when omitted.")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_exec,
        examples: ["secrets exec --as m --secret db-prod -- psql"],
    ));
    r.insert(cmd!(
        path: ["secrets", "add"],
        summary: "Register a new secret's policy: backend + key, never a value (the secrets broker never stores one). No consumers/sharing/TOTP unless given. --backend defaults to `age` (the built-in age-encrypted store) when omitted.",
        args: [arg!("name", "string", true, "The secret's nickname.")],
        flags: [
            flag!("backend", "string", "The named backend (backends.json) that fetches this secret's value. Defaults to `age` (the built-in age-encrypted store) when omitted."),
            flag!("key", "string", "The backend-specific key/identifier substituted into that backend's fetch-command template."),
            flag!("require-totp", "bool", "Require a fresh TOTP code to resolve — the policy is born gated. Unresolvable until this host has run `secrets enroll`; once enrolled, verified live against the enrolled TOTP secret on every resolve (`secrets set-totp` flips this later without re-adding)."),
            flag!("consumers", "string", "Comma-separated consumer names allowed to resolve this secret (empty/omitted = any consumer).")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_add,
        examples: ["secrets add db-prod --backend pass --key prod/db --consumers m"],
    ));
    r.insert(cmd!(
        path: ["secrets", "rm"],
        summary: "Remove a secret's policy. The backend's own store is untouched — this only forgets aoide's policy record.",
        args: [arg!("name", "string", true, "The secret's nickname.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_rm,
        examples: ["secrets rm db-prod"],
    ));
    r.insert(cmd!(
        path: ["secrets", "grant"],
        summary: "Add one consumer to a secret's policy.",
        args: [
            arg!("name", "string", true, "The secret's nickname."),
            arg!("consumer", "string", true, "The consumer name to grant.")
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_grant,
        examples: ["secrets grant db-prod m"],
    ));
    r.insert(cmd!(
        path: ["secrets", "revoke"],
        summary: "Remove one consumer from a secret's policy.",
        args: [
            arg!("name", "string", true, "The secret's nickname."),
            arg!("consumer", "string", true, "The consumer name to revoke.")
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_revoke,
        examples: ["secrets revoke db-prod m"],
    ));
    r.insert(cmd!(
        path: ["secrets", "enroll"],
        summary: "Enroll this host for TOTP: generate a fresh secret and print its otpauth:// URI + base32 form (plus a QR code when `qrencode` is on PATH). ONE enrollment per host — pass --force to regenerate (old codes stop working immediately), or --show to reprint the EXISTING enrollment's URI/QR without rotating anything. --force and --show are mutually exclusive. CLI-only: the secret is printed directly to stdout, never through this envelope.",
        args: [],
        flags: [
            flag!("force", "bool", "Regenerate the secret even if one is already enrolled on this host. Invalidates every previously issued code."),
            flag!("show", "bool", "Reprint the existing enrollment's otpauth:// URI + base32 + QR without generating or rotating anything. Errors if no enrollment exists yet.")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_enroll,
        examples: ["secrets enroll", "secrets enroll --force", "secrets enroll --show"],
    ));
    r.insert(cmd!(
        path: ["secrets", "put"],
        summary: "Store a value for an EXISTING secret's policy, read from stdin (never argv) — prompts on stderr with input hidden when stdin is a terminal, reads piped bytes byte-identically otherwise. Warns and asks [y/N] before overwriting a secret that already has a stored value on a tty; a piped/non-interactive attempt to overwrite is refused and told to pass --force. CLI-only — no TOTP, since put is admin-side, not agent-facing. The named policy's backend must carry a `set` template (the built-in `file`/`age` backends both have one by default).",
        args: [arg!("name", "string", true, "The secret's nickname — must already have a policy (`secrets add` first).")],
        flags: [
            flag!("force", "bool", "Store the value even if the secret already has one, skipping the overwrite confirmation. Required to overwrite from a piped/non-interactive stdin (no one to confirm with there).")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_put,
        examples: [
            "printf %s hunter2 | aoide secrets put db-prod",
            "aoide secrets put db-prod",
            "printf %s hunter2 | aoide secrets put db-prod --force"
        ],
    ));
    r.insert(cmd!(
        path: ["secrets", "set-totp"],
        summary: "Flip an EXISTING secret's requireTotp bit on or off, without hand-editing policy.json. Idempotent: re-setting the same state reports \"unchanged\" and writes nothing.",
        args: [
            arg!("name", "string", true, "The secret's nickname — must already have a policy (`secrets add` first)."),
            arg!("state", "string", true, "`on` or `off`.")
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_set_totp,
        examples: ["secrets set-totp db-prod on", "secrets set-totp db-prod off"],
    ));
    r.insert(cmd!(
        path: ["secrets", "automate"],
        summary: "Manage an EXISTING secret's automation gate. `on`/`off` flips whether the LISTED consumers resolve without a TOTP code (every other caller stays gated by requireTotp as before); `grant`/`revoke <consumer>` edits which consumers are listed. Idempotent: re-setting a state, or granting/revoking a consumer already in/out of the list, reports \"unchanged\" and writes nothing.",
        args: [
            arg!("name", "string", true, "The secret's nickname — must already have a policy (`secrets add` first)."),
            arg!("action", "string", true, "`on` | `off` | `grant` | `revoke`."),
            arg!("consumer", "string", false, "Consumer name — required for `grant`/`revoke`, ignored for `on`/`off`.")
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_automate,
        examples: [
            "secrets automate db-prod on",
            "secrets automate db-prod grant m",
            "secrets automate db-prod revoke m",
            "secrets automate db-prod off"
        ],
    ));
    r.insert(cmd!(
        path: ["secrets", "expose"],
        summary: "Flip an EXISTING secret's remote-reachability bit on or off. No behavior change today — no non-local entry point exists yet — but every non-local path added later (mesh replication, a network door) must refuse a secret whose remote bit is off. Idempotent: re-setting the same state reports \"unchanged\" and writes nothing.",
        args: [
            arg!("name", "string", true, "The secret's nickname — must already have a policy (`secrets add` first)."),
            arg!("state", "string", true, "`on` or `off`.")
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_expose,
        examples: ["secrets expose db-prod on", "secrets expose db-prod off"],
    ));
    r.insert(cmd!(
        path: ["secrets", "pending"],
        summary: "List every parked TOTP-gated resolve waiting on a code (id, secret, consumer, requestedAt) — never a value. Operator-side over the socket, same as put/exec: CLI-only, but NOT an admin/euid command (it only reads in-memory broker state, no policy.json write).",
        args: [],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_pending,
        examples: ["secrets pending"],
    ));
    r.insert(cmd!(
        path: ["secrets", "approve"],
        summary: "Complete a parked resolve with a TOTP code, releasing the value down the ORIGINAL requesting connection (never into this command's own reply). Invalid/expired code: the ask stays parked and the replay ledger is unburned.",
        args: [arg!("id", "string", true, "The parked ask's id, from `secrets pending`.")],
        flags: [flag!("totp", "string", "The TOTP code to validate against this host's enrollment.")],
        gated: false,
        implemented: true,
        handler: handle_secrets_approve,
        examples: ["secrets approve 3 --totp 123456"],
    ));
    r.insert(cmd!(
        path: ["secrets", "dismiss"],
        summary: "Refuse a parked resolve outright — the original requesting connection gets a clean \"dismissed\" refusal, no code needed.",
        args: [arg!("id", "string", true, "The parked ask's id, from `secrets pending`.")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_dismiss,
        examples: ["secrets dismiss 3"],
    ));
    r.insert(cmd!(
        path: ["secrets", "watch"],
        summary: "Foreground, line-mode watcher: tail-follows the broker-owned events feed and narrates every broker event (released/parked/completed/dismissed/expired). On a terminal, also prompts inline for each parked ask — [a]pprove with a hidden TOTP code, [d]ismiss, or [i]gnore (stays parked). --json emits one event object per line instead, narration-only. --popup swaps the terminal prompt for a zenity code-entry dialog on each parked ask (unlock-gated, parked-only; requires zenity on PATH) — mutually exclusive with --json. CLI-only, operator-side (same door gate as pending/approve/dismiss) — blocks until Ctrl-C.",
        args: [],
        flags: [flag!(
            "popup",
            "bool",
            "Surface each parked ask as a zenity --entry --hide-text dialog instead of the terminal's [a]/[d]/[i] prompt. Unlock-gated (holds the dialog while the session is locked, via loginctl LockedHint OR'd with an AOIDE_SECRETS_LOCKER /proc scan, default `hyprlock`) and parked-only (released/completed/dismissed/expired still narrate, never popup). Requires zenity on PATH. Mutually exclusive with --json."
        )],
        gated: false,
        implemented: true,
        handler: handle_secrets_watch,
        examples: ["secrets watch", "secrets watch --json", "secrets watch --popup"],
    ));
    r.insert(cmd!(
        path: ["secrets", "migrate"],
        summary: "Move an EXISTING secret's stored value from its policy's current backend to a target backend (default `age`), then flip the policy's backend field. Admin command, direct-home (mirrors add/rm/grant, not put/exec's socket round trip). Fetches via the current backend, stores via the target first, flips policy.json only after the new value is durably stored, then removes the old value LAST — only when the source backend is a built-in (file/age) whose value path this crate can derive on its own.",
        args: [arg!("name", "string", true, "The secret's nickname — must already have a policy (`secrets add` first).")],
        flags: [flag!("backend", "string", "The target backend to migrate onto. Defaults to `age` (the built-in age-encrypted store) when omitted.")],
        gated: false,
        implemented: true,
        handler: handle_secrets_migrate,
        examples: ["secrets migrate db-prod", "secrets migrate db-prod --backend age"],
    ));
    r.insert(cmd!(
        path: ["secrets", "allow-remote-origin"],
        summary: "Flip an EXISTING secret's remote-origin admission bit on or off (LANE IDENTITY P-ID4). Off (the default) refuses a resolve whose CALLER SESSION is positively attested as remote-origin (a sealed `peer:*` originClass — a session a remote peer created); on admits it. Distinct from `expose` (remote = may the secret be served through a non-local entry point) and `automate` (may listed consumers skip TOTP) — this gates WHO locally asks, by kernel-attested provenance. Unidentified callers are untouched by this gate. Idempotent: re-setting the same state reports \"unchanged\" and writes nothing.",
        args: [
            arg!("name", "string", true, "The secret's nickname — must already have a policy (`secrets add` first)."),
            arg!("state", "string", true, "`on` or `off`.")
        ],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_allow_remote_origin,
        examples: ["secrets allow-remote-origin db-prod on", "secrets allow-remote-origin db-prod off"],
    ));
}

/// See `crate::broker`'s module doc for the accept loop this launch record
/// hands off to (in the owning app crate's `special` hook, not here).
fn handle_secrets_serve(inv: &Invocation) -> Outcome {
    match inv.door {
        Door::Cli => Outcome::ok("secrets.serve", "starting the secrets broker").with_data(json!({
            "secretsHome": home::secrets_home().to_string_lossy(),
            "socket": crate::socket::socket_path().to_string_lossy(),
        })),
        _ => Outcome::usage(
            "secrets.serve",
            "secrets serve is a long-running broker; run `aoide secrets serve` from a terminal (not over this door)",
        ),
    }
}

/// See `crate::client`'s module doc for the resolve+exec flow this launch
/// record hands off to (in the owning app crate's `special` hook).
fn handle_secrets_exec(inv: &Invocation) -> Outcome {
    match inv.door {
        Door::Cli => Outcome::ok("secrets.exec", "resolving secret to exec"),
        _ => Outcome::usage(
            "secrets.exec",
            "secrets exec spawns a child with inherited stdio; run it from a CLI terminal (not over this door)",
        ),
    }
}

/// See `crate::enroll`'s module doc for the secret-generation/persistence/
/// printing flow this hands off to (in the owning app crate's `special`
/// hook, not here — same split as `handle_secrets_serve`/`handle_secrets_exec`
/// above). This handler itself does no secrets-home I/O: it only gates the
/// door (reusing [`require_cli`], same as the CRUD quartet below) and
/// returns a plain confirmation `Outcome` with no secret content — the
/// `secretsHome` field mirrors `handle_secrets_serve`'s own `with_data`.
fn handle_secrets_enroll(inv: &Invocation) -> Outcome {
    let cmd = "secrets.enroll";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    if inv.flag_present("force") && inv.flag_present("show") {
        return Outcome::usage(cmd, "secrets enroll: --force and --show are mutually exclusive");
    }
    let message = if inv.flag_present("show") { "reprinting enrollment" } else { "enrolling TOTP on this host" };
    Outcome::ok(cmd, message).with_data(json!({
        "secretsHome": home::secrets_home().to_string_lossy(),
    }))
}

/// Shared door gate for the admin quartet (`add`/`rm`/`grant`/`revoke`):
/// CLI-only, same shape as `handle_secrets_serve`/`handle_secrets_exec`'s own
/// door check (bounce-fix item 2, P-V2 review). Returns `Some(hint)` on any
/// non-`Cli` door — the caller must return it immediately, before touching
/// `store::load_policies`/`store::save_policies`, so a gated call never
/// mutates `policy.json`.
fn require_cli(inv: &Invocation, cmd: &str) -> Option<Outcome> {
    match inv.door {
        Door::Cli => None,
        _ => Some(Outcome::usage(
            cmd,
            "secrets policy admin commands (add/rm/grant/revoke) are CLI-only; run this from a terminal (not over this door)",
        )),
    }
}

/// The yomi-strix incident's guard (2026-08-22, this crate's `AGENTS.md`/
/// `home.rs`'s module doc): refuses an admin command BEFORE it ever calls
/// `store::load_policies`/`store::save_policies` when this process's
/// effective uid isn't the secrets home's owning uid — `plain sudo`
/// (euid 0) is explicitly wrong, not a free pass, because root CAN write
/// regardless of ownership, which is exactly what silently reowned
/// `policy.json` to `root:root` and bricked the broker (and every
/// subsequent admin command, including the correctly-spelled `sudo -u
/// aoide-secrets` retry) in the field. Called immediately after
/// [`require_cli`] in every handler below. `subcommand` is the bare
/// command word (`"add"`, not `"secrets.add"`) — it lands in the
/// corrective `sudo -u aoide-secrets aoide secrets <subcommand> ...`
/// spelling the refusal teaches.
fn require_admin_identity(cmd: &str, subcommand: &str) -> Option<Outcome> {
    home::admin_identity_check(&home::secrets_home(), subcommand).map(|msg| Outcome::error(cmd, msg))
}

/// `secrets add`'s backend when `--backend` is omitted (P-G1, task #70 —
/// DEFAULT FLIP: was implicitly `file`-shaped in every existing example
/// in this crate's own docs, never actually enforced as a code default
/// before this change; `--backend` was REQUIRED before P-G1, not merely
/// defaulted). Stored policy rows are untouched by this flip — an
/// EXISTING policy's `backend` field always wins; this only decides what a
/// brand-new `secrets add` with no `--backend` records.
const DEFAULT_BACKEND: &str = "age";

/// Task #79: try the broker socket first (an `{op:"admin",command:...}`
/// request carrying `fields` plus `op`/`command`), falling back to the
/// direct-write path — [`require_admin_identity`] then `direct()`, running
/// the SAME mutation from [`crate::admin`] locally — ONLY when nothing is
/// listening (`crate::client::AdminError::NoSocket`). Any other socket
/// error (including the broker's own authoritative `{"ok":false}` denial —
/// `client::admin_request`'s own doc) is reported outright, never silently
/// downgraded: a live-but-sick daemon must never be bypassed into a TOCTOU
/// race against a direct write landing underneath it. Reports which path
/// executed via `Outcome::with_data({"path":"broker"|"direct"})` — the
/// message/changed-keys shape is otherwise identical either way, since both
/// paths report through the same [`crate::admin::AdminOutcome`] fields.
fn admin_dispatch(
    cmd: &str,
    subcommand: &str,
    mut fields: serde_json::Map<String, serde_json::Value>,
    direct: impl FnOnce() -> Result<crate::admin::AdminOutcome, String>,
) -> Outcome {
    fields.insert("op".to_string(), json!("admin"));
    fields.insert("command".to_string(), json!(subcommand));
    match crate::client::admin_request(&crate::socket::socket_path(), serde_json::Value::Object(fields)) {
        Ok(reply) => {
            let message = reply.get("message").and_then(serde_json::Value::as_str).unwrap_or_default().to_string();
            let changed: Vec<String> = reply
                .get("changed")
                .and_then(serde_json::Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let mut outcome = Outcome::ok(cmd, message).with_data(json!({"path": "broker"}));
            if !changed.is_empty() {
                outcome = outcome.changed(changed);
            }
            outcome
        }
        Err(crate::client::AdminError::NoSocket) => {
            if let Some(hint) = require_admin_identity(cmd, subcommand) {
                return hint;
            }
            match direct() {
                Ok(r) => {
                    let mut outcome = Outcome::ok(cmd, r.message).with_data(json!({"path": "direct"}));
                    if !r.changed.is_empty() {
                        outcome = outcome.changed(r.changed);
                    }
                    outcome
                }
                Err(e) => Outcome::error(cmd, e),
            }
        }
        Err(crate::client::AdminError::Other(e)) => Outcome::error(cmd, e),
    }
}

fn handle_secrets_add(inv: &Invocation) -> Outcome {
    let cmd = "secrets.add";
    const USAGE: &str = "usage: secrets add <name> --key <key> [--backend <backend>]";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, USAGE);
    };
    if !valid_secret_name(&name) {
        return Outcome::usage(
            cmd,
            format!(
                "invalid secret name `{name}` (must be lowercase [a-z0-9-], no leading/trailing/doubled \
                 hyphen) — {USAGE}"
            ),
        );
    }
    let backend = inv.flags.get("backend").cloned().unwrap_or_else(|| DEFAULT_BACKEND.to_string());
    let Some(key) = inv.flags.get("key").cloned() else {
        return Outcome::usage(cmd, format!("secrets add: missing --key <key> — {USAGE}"));
    };
    let require_totp = inv.flag_present("require-totp");
    let consumers: Vec<String> = inv
        .flags
        .get("consumers")
        .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();

    let fields = serde_json::Map::from_iter([
        ("name".to_string(), json!(name.clone())),
        ("backend".to_string(), json!(backend.clone())),
        ("key".to_string(), json!(key.clone())),
        ("requireTotp".to_string(), json!(require_totp)),
        ("consumers".to_string(), json!(consumers.clone())),
    ]);
    admin_dispatch(cmd, "add", fields, || {
        crate::admin::add(&home::secrets_home(), &name, &backend, &key, require_totp, consumers)
    })
}

fn handle_secrets_rm(inv: &Invocation) -> Outcome {
    let cmd = "secrets.rm";
    const USAGE: &str = "usage: secrets rm <name>";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, USAGE);
    };
    let fields = serde_json::Map::from_iter([("name".to_string(), json!(name.clone()))]);
    admin_dispatch(cmd, "rm", fields, || crate::admin::rm(&home::secrets_home(), &name))
}

/// Shared shape behind `grant`/`revoke`: both take `<name> <consumer>` and
/// differ only in `want_listed` (`true` pushes the consumer if absent,
/// `false` removes it if present — [`crate::admin::grant`]/[`crate::admin::
/// revoke`]'s own job). `subcommand` names the bare word for the wire
/// request and [`require_admin_identity`]'s corrective spelling.
fn edit_consumer(inv: &Invocation, cmd: &str, subcommand: &str, usage: &str, want_listed: bool) -> Outcome {
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, format!("secrets {subcommand}: missing <name> — {usage}"));
    };
    let Some(consumer) = inv.args.get(1).cloned() else {
        return Outcome::usage(cmd, format!("secrets {subcommand}: missing <consumer> — {usage}"));
    };
    let fields = serde_json::Map::from_iter([
        ("name".to_string(), json!(name.clone())),
        ("consumer".to_string(), json!(consumer.clone())),
    ]);
    admin_dispatch(cmd, subcommand, fields, || {
        let home = home::secrets_home();
        if want_listed {
            crate::admin::grant(&home, &name, &consumer)
        } else {
            crate::admin::revoke(&home, &name, &consumer)
        }
    })
}

fn handle_secrets_grant(inv: &Invocation) -> Outcome {
    edit_consumer(inv, "secrets.grant", "grant", "usage: secrets grant <name> <consumer>", true)
}

fn handle_secrets_revoke(inv: &Invocation) -> Outcome {
    edit_consumer(inv, "secrets.revoke", "revoke", "usage: secrets revoke <name> <consumer>", false)
}

/// `secrets put <name>` (P-V4c, `--force` P-67) — CLI-only via the SAME
/// [`require_cli`] gate as the admin quartet (module doc: an agent putting
/// values is exactly what the design forbids), then a PLAIN delegation to
/// `crate::client::run_put`, which reads the value from stdin, warns +
/// confirms before an overwrite (module doc), and does the socket round
/// trip(s). The returned [`Outcome`]'s message is exactly what `run_put`
/// reports ("stored" vs. "replaced" on success) — `crate::client::
/// run_put`'s `Result<String, String>` carries no VALUE on either arm
/// (put's own wire reply never has one either), so there is nothing here
/// that could put the secret's value on this envelope even by accident.
fn handle_secrets_put(inv: &Invocation) -> Outcome {
    let cmd = "secrets.put";
    const USAGE: &str = "usage: secrets put <name> [--force] (value read from stdin)";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, USAGE);
    };
    if !valid_secret_name(&name) {
        return Outcome::usage(
            cmd,
            format!(
                "invalid secret name `{name}` (must be lowercase [a-z0-9-], no leading/trailing/doubled \
                 hyphen) — {USAGE}"
            ),
        );
    }
    let force = inv.flag_present("force");
    match crate::client::run_put(&name, &crate::socket::socket_path(), force) {
        Ok(message) => Outcome::ok(cmd, message),
        Err(e) => Outcome::error(cmd, e),
    }
}

/// `secrets set-totp <name> on|off` — the direct replacement for the
/// hand-edited `jq` one-liner against `policy.json` this command exists to
/// retire. Same `require_cli` gate as the rest of the admin surface; an
/// unknown secret name is a clean [`Outcome::error`], never a silent
/// no-op. Idempotent (house rule 2 — "report exactly what changed"):
/// re-setting the state a policy already has writes NOTHING and reports
/// "unchanged" rather than calling `.changed(...)` on a write that never
/// happened.
fn handle_secrets_set_totp(inv: &Invocation) -> Outcome {
    let cmd = "secrets.set-totp";
    const USAGE: &str = "usage: secrets set-totp <name> on|off";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, format!("secrets set-totp: missing <name> — {USAGE}"));
    };
    let Some(state) = inv.args.get(1).cloned() else {
        return Outcome::usage(cmd, format!("secrets set-totp: missing on|off — {USAGE}"));
    };
    let want = match state.as_str() {
        "on" => true,
        "off" => false,
        _ => return Outcome::usage(cmd, format!("secrets set-totp expects `on` or `off`, got `{state}` — {USAGE}")),
    };
    let fields =
        serde_json::Map::from_iter([("name".to_string(), json!(name.clone())), ("state".to_string(), json!(state))]);
    admin_dispatch(cmd, "set-totp", fields, || crate::admin::set_totp(&home::secrets_home(), &name, want))
}

/// `secrets automate <name> on|off | grant|revoke <consumer>` (P-N1) — the
/// admin command behind `crate::policy::Policy::automation`. Same
/// `require_cli` + `require_admin_identity` gate, same idempotency
/// discipline as `set-totp` above: a state already in place, or a
/// consumer already granted/revoked, reports "unchanged" and never
/// rewrites `policy.json`. `grant`/`revoke`'s `<consumer>` is checked with
/// the SAME [`valid_secret_name`] validation this crate already holds
/// every other name to — a malformed consumer name is a usage error, not
/// a silently-accepted string.
fn handle_secrets_automate(inv: &Invocation) -> Outcome {
    let cmd = "secrets.automate";
    const USAGE: &str = "usage: secrets automate <name> on|off | secrets automate <name> grant|revoke <consumer>";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, format!("secrets automate: missing <name> — {USAGE}"));
    };
    let Some(action) = inv.args.get(1).cloned() else {
        return Outcome::usage(cmd, format!("secrets automate: missing on|off|grant|revoke — {USAGE}"));
    };

    match action.as_str() {
        "on" | "off" => {
            let want = action == "on";
            let fields = serde_json::Map::from_iter([
                ("name".to_string(), json!(name.clone())),
                ("action".to_string(), json!(action.clone())),
            ]);
            admin_dispatch(cmd, "automate", fields, || crate::admin::automate_toggle(&home::secrets_home(), &name, want))
        }
        "grant" | "revoke" => {
            let Some(consumer) = inv.args.get(2).cloned() else {
                return Outcome::usage(cmd, format!("secrets automate {name} {action}: missing <consumer> — {USAGE}"));
            };
            if !valid_secret_name(&consumer) {
                return Outcome::usage(
                    cmd,
                    format!(
                        "invalid consumer name `{consumer}` (must be lowercase [a-z0-9-], no leading/trailing/doubled \
                         hyphen) — {USAGE}"
                    ),
                );
            }
            let want_listed = action == "grant";
            let fields = serde_json::Map::from_iter([
                ("name".to_string(), json!(name.clone())),
                ("action".to_string(), json!(action.clone())),
                ("consumer".to_string(), json!(consumer.clone())),
            ]);
            admin_dispatch(cmd, "automate", fields, || {
                crate::admin::automate_consumer(&home::secrets_home(), &name, &consumer, want_listed)
            })
        }
        _ => Outcome::usage(cmd, format!("secrets automate expects on|off|grant|revoke, got `{action}` — {USAGE}")),
    }
}

/// `secrets expose <name> on|off` (P-N1) — flips `crate::policy::
/// Policy::remote`. Same shape as `handle_secrets_set_totp` exactly:
/// same admin gate, same idempotent "unchanged" reporting.
fn handle_secrets_expose(inv: &Invocation) -> Outcome {
    let cmd = "secrets.expose";
    const USAGE: &str = "usage: secrets expose <name> on|off";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, format!("secrets expose: missing <name> — {USAGE}"));
    };
    let Some(state) = inv.args.get(1).cloned() else {
        return Outcome::usage(cmd, format!("secrets expose: missing on|off — {USAGE}"));
    };
    let want = match state.as_str() {
        "on" => true,
        "off" => false,
        _ => return Outcome::usage(cmd, format!("secrets expose expects `on` or `off`, got `{state}` — {USAGE}")),
    };
    let fields =
        serde_json::Map::from_iter([("name".to_string(), json!(name.clone())), ("state".to_string(), json!(state))]);
    admin_dispatch(cmd, "expose", fields, || crate::admin::expose(&home::secrets_home(), &name, want))
}

/// `secrets allow-remote-origin <name> on|off` (LANE IDENTITY P-ID4) —
/// flips the policy's `allowRemoteOrigin` bit, the remote-ORIGIN admission
/// axis `broker::resolve_gate`'s origin gate reads (see that module's
/// "The origin gate" section for the boundary it enforces, exactly). Same
/// admin family spelling as `expose`/`set-totp` (`<name> on|off`, the
/// hyphenated-command precedent `set-totp` established), same
/// `require_cli` + broker-first `admin_dispatch` routing, same idempotency:
/// re-setting the current state reports "unchanged" and writes nothing.
fn handle_secrets_allow_remote_origin(inv: &Invocation) -> Outcome {
    let cmd = "secrets.allow-remote-origin";
    const USAGE: &str = "usage: secrets allow-remote-origin <name> on|off";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, format!("secrets allow-remote-origin: missing <name> — {USAGE}"));
    };
    let Some(state) = inv.args.get(1).cloned() else {
        return Outcome::usage(cmd, format!("secrets allow-remote-origin: missing on|off — {USAGE}"));
    };
    let want = match state.as_str() {
        "on" => true,
        "off" => false,
        _ => {
            return Outcome::usage(
                cmd,
                format!("secrets allow-remote-origin expects `on` or `off`, got `{state}` — {USAGE}"),
            )
        }
    };
    let fields =
        serde_json::Map::from_iter([("name".to_string(), json!(name.clone())), ("state".to_string(), json!(state))]);
    admin_dispatch(cmd, "allow-remote-origin", fields, || {
        crate::admin::allow_remote_origin(&home::secrets_home(), &name, want)
    })
}

/// `secrets pending` (P-N2) — CLI-only via the SAME [`require_cli`] gate as
/// `put`/`exec`, but deliberately **NOT** [`require_admin_identity`]: this
/// is the operator-side socket surface (task requirement — "like put/exec,
/// NOT admin/euid commands"), reading in-memory broker state over the socket
/// rather than `policy.json`, so the euid-ownership guard that protects
/// `policy.json` writes doesn't apply here. The list `crate::client::
/// pending` returns is value-free by construction (`PendingAsk` has no
/// value field at all); this handler only re-shapes it into JSON, adding
/// nothing.
fn handle_secrets_pending(inv: &Invocation) -> Outcome {
    let cmd = "secrets.pending";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    match crate::client::pending(&crate::socket::socket_path()) {
        Ok(asks) => {
            let data: Vec<serde_json::Value> = asks
                .iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "secret": a.secret,
                        "consumer": a.consumer,
                        "requestedAt": a.requested_at,
                        "peerUid": a.peer_uid,
                    })
                })
                .collect();
            Outcome::ok(cmd, format!("{} pending ask(s)", asks.len())).with_data(json!({ "pending": data }))
        }
        Err(e) => Outcome::error(cmd, e),
    }
}

/// `secrets approve <id> --totp <code>` (P-N2) — same operator-side gate as
/// `secrets pending` above (CLI-only, no admin-identity check). Delegates
/// straight to `crate::client::approve`, whose `Result<(), String>` carries
/// no value on either arm (the wire's own `approve` reply never has one —
/// `broker::handle_approve`'s own doc: the value goes down the ORIGINAL
/// parked connection, never this reply).
fn handle_secrets_approve(inv: &Invocation) -> Outcome {
    let cmd = "secrets.approve";
    const USAGE: &str = "usage: secrets approve <id> --totp <code>";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(id) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, format!("secrets approve: missing <id> — {USAGE}"));
    };
    let Some(totp) = inv.flags.get("totp").cloned() else {
        return Outcome::usage(cmd, format!("secrets approve: missing --totp <code> — {USAGE}"));
    };
    match crate::client::approve(&crate::socket::socket_path(), &id, &totp) {
        Ok(()) => Outcome::ok(cmd, format!("approved pending ask `{id}`")).changed(vec![format!("pending:{id}")]),
        Err(e) => Outcome::error(cmd, e),
    }
}

/// `secrets dismiss <id>` (P-N2) — same operator-side gate as `secrets
/// pending`/`secrets approve` above. The parked caller gets a clean
/// "dismissed" refusal on its own connection; this reply only confirms the
/// dismissal happened, no value ever exists on this path at all.
fn handle_secrets_dismiss(inv: &Invocation) -> Outcome {
    let cmd = "secrets.dismiss";
    const USAGE: &str = "usage: secrets dismiss <id>";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(id) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, format!("secrets dismiss: missing <id> — {USAGE}"));
    };
    match crate::client::dismiss(&crate::socket::socket_path(), &id) {
        Ok(()) => Outcome::ok(cmd, format!("dismissed pending ask `{id}`")).changed(vec![format!("pending:{id}")]),
        Err(e) => Outcome::error(cmd, e),
    }
}

/// `secrets watch` (this commit) — special-cased the SAME way as `serve`/
/// `exec`/`enroll`: this handler only gates the door (CLI-only, same
/// [`require_cli`] as `pending`/`approve`/`dismiss` — NOT
/// [`require_admin_identity`], since watch touches no `policy.json` either,
/// only the broker-owned events feed (P-G4, task #77 — corrected from the
/// mirrored aoide log, `watch.rs`'s own module doc) and the broker's
/// in-memory registry over the socket), refuses the `--popup`+`--json`
/// combination as a usage error
/// (tracker #71 Part 2 — the two modes both own "how a parked ask gets
/// completed" and can't both drive it), and records the launch through the
/// single audit log; the actual foreground loop (`crate::watch::run`) is
/// dispatched from `cli`'s `special` hook, blocking forever until Ctrl-C —
/// see that crate's `run_cli` doc comment and `crate::watch`'s own module
/// doc.
fn handle_secrets_watch(inv: &Invocation) -> Outcome {
    let cmd = "secrets.watch";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    if inv.flag_present("popup") && inv.flag_present("json") {
        return Outcome::usage(
            cmd,
            "secrets watch: --popup and --json are mutually exclusive — --popup replaces the terminal prompt \
             with a zenity dialog, --json emits narration-only machine-readable lines; pick one",
        );
    }
    Outcome::ok(cmd, "watching secret events")
}

/// Name-only audit line for `secrets migrate` (P-G2, task #72) —
/// `EventClass::Secret`, the SAME class every other value-adjacent line in
/// this crate uses (`broker.rs`'s `audit_resolve`/`audit_put`/etc.), same
/// "never the value, never the key" discipline. Unlike those, this call
/// site lives here, not in `broker.rs`: migrate is a direct-home admin command
/// (`handle_secrets_migrate`'s own doc) that never runs inside the broker
/// daemon process, so there is no daemon-owned `audit.log` for it to also
/// write to (that file is `0700` broker-uid and unreachable from an
/// ordinary admin invocation anyway) — only the mirrored aoide log, the
/// SAME `aoide_protocol::audit` call every admin command's generic dispatch
/// audit already goes through, just with the richer, migrate-specific
/// message this one extra line adds. `door` is the invocation's own door
/// (always `Cli` in practice — `require_cli` already refused anything
/// else) rather than a hardcoded `Door::Daemon`, since this code is not
/// the daemon speaking.
fn audit_migrate(door: Door, name: &str, source: &str, target: &str, status: &str, reason: Option<&str>) {
    let message = match reason {
        Some(r) => format!("migrate `{name}`: {source} -> {target}: {status} ({r})"),
        None => format!("migrate `{name}`: {source} -> {target}: {status}"),
    };
    let _ = aoide_protocol::audit(
        &aoide_protocol::default_audit_log(),
        door,
        aoide_protocol::EventClass::Secret,
        "secrets.migrate",
        status,
        &message,
    );
}

/// `secrets migrate <name> [--backend <target>]` (P-G2, task #72) — moves
/// an EXISTING secret's stored value from its policy's CURRENT backend to
/// a TARGET backend (default `age`, [`DEFAULT_BACKEND`]), then flips the
/// policy's own `backend` field. Admin command, same door + euid gate as
/// `add`/`rm`/`grant` (`require_cli` + `require_admin_identity`) — mirrors
/// their DIRECT-HOME wire shape exactly: no socket round trip, the same
/// `store::load_policies`/`save_policies` round trip every other CRUD command
/// here already uses. The moved value exists ONLY as a local `String`
/// inside this function, from [`crate::backend::fetch_value`]'s return to
/// [`crate::backend::store_value`]'s own argument — never an `Outcome`
/// field, never argv, never audited (`AGENTS.md`'s "never the value"
/// discipline, held crate-wide).
///
/// Ordering is safety-critical (`README.md`'s "Migrating a secret between
/// backends"): the NEW ciphertext is fetched and durably stored via the
/// TARGET backend BEFORE the policy is flipped and saved; the OLD value is
/// removed LAST, and only for a built-in backend whose on-disk path is
/// derivable ([`crate::backend::remove_builtin_value`]). Any failure before
/// the policy flip leaves `policy.json`, `backends.json`, and every
/// backend's own store untouched.
fn handle_secrets_migrate(inv: &Invocation) -> Outcome {
    let cmd = "secrets.migrate";
    const USAGE: &str = "usage: secrets migrate <name> [--backend <target>]";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, USAGE);
    };
    let target = inv.flags.get("backend").cloned().unwrap_or_else(|| DEFAULT_BACKEND.to_string());
    let door = inv.door;

    let fields = serde_json::Map::from_iter([
        ("name".to_string(), json!(name.clone())),
        ("target".to_string(), json!(target.clone())),
    ]);
    // `crate::admin::migrate`'s own ordering (fetch -> maybe mint -> store
    // -> flip+save -> remove-old-last) is unchanged by this phase, whether
    // it runs here (direct-write fallback) or inside the broker's
    // `put_lock` critical section (`broker::handle_admin`) — this closure
    // only adds the one thing that stays HERE regardless of which path
    // ran: `audit_migrate`'s own richer source->target audit line
    // (`commands.rs`'s own audit mechanism, distinct from — and in
    // addition to — `broker::audit_admin`'s generic line on the broker
    // path).
    admin_dispatch(cmd, "migrate", fields, || match crate::admin::migrate(&home::secrets_home(), door, &name, &target) {
        Ok((outcome, source, target)) => {
            let status = if outcome.changed.is_empty() { "unchanged" } else { "migrated" };
            audit_migrate(door, &name, &source, &target, status, None);
            Ok(outcome)
        }
        Err(crate::admin::MigrateError { message, source }) => {
            // `source` is the REAL backend name whenever `crate::admin::
            // migrate` got far enough to know one (`MigrateError`'s own
            // doc) — only `"?"` on the one failure mode that truly
            // precedes knowing a source at all (no policy for `name`).
            // Same fidelity the pre-#79 direct path's multi-stage
            // `audit_migrate` calls always had.
            audit_migrate(door, &name, &source, &target, "refused", Some(&message));
            Err(message)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;
    use aoide_protocol::output::Status;
    use std::collections::BTreeMap;

    fn with_secrets_home<T>(tag: &str, f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_HOME").ok();
        let dir = std::env::temp_dir().join(format!(
            "aoide-secrets-commands-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("AOIDE_SECRETS_HOME", &dir);
        // Task #79: `admin_dispatch` tries the REAL socket
        // `crate::socket::socket_path()` resolves to FIRST — which, unlike
        // `AOIDE_SECRETS_HOME`, is NOT derived from this tempdir at all
        // (`socket.rs`'s own module doc: hardcoded so an env-less client
        // shell finds the real deployed broker). On a box that happens to
        // be running a real `aoide secrets serve` (this crate's own dev/
        // deployment host, `/run/aoide-secrets/secrets.sock`), an admin-command
        // test that didn't override this would silently talk to THAT real
        // daemon instead of exercising the direct-write fallback these
        // tests exist to prove — never acceptable for a unit test to touch
        // live system state. Pointing at a path inside this SAME
        // never-existing tempdir guarantees `ENOENT` on every connect
        // attempt, so every admin-command test hermetically takes the
        // `AdminError::NoSocket` fallback branch, exactly like every one of
        // these tests behaved before task #79 introduced the socket path
        // at all.
        // Deliberately a SHORT, FIXED path, never `dir.join(...)`:
        // `std::env::temp_dir()` plus this function's own long, descriptive
        // tag/pid/nanosecond suffix can push a socket path past `AF_UNIX`'s
        // 108-byte `sun_path` limit, which `client::unix_sockaddr` (rightly)
        // refuses as `InvalidInput` — a genuine `AdminError::Other`, not
        // `NoSocket`, which would skip the fallback branch entirely rather
        // than exercise it (found live: `migrate_onto_age_warns_that_age_
        // key_is_now_the_only_decryptor`'s tag alone was long enough to
        // trip this). Serialized under `env_lock()` like every other env
        // mutation in this fixture, so the one shared literal path is safe
        // across tests despite never being unique per-tag.
        let saved_socket = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        std::env::set_var("AOIDE_SECRETS_SOCKET", "/nonexistent/aoide-secrets-test/no-such-broker.sock");
        let result = f(&dir);
        match saved_socket {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
        std::fs::remove_dir_all(&dir).ok();
        result
    }

    fn inv(door: Door, path: &[&str], args: &[&str], flags: &[(&str, &str)]) -> Invocation {
        let mut flag_map = BTreeMap::new();
        for (k, v) in flags {
            flag_map.insert(k.to_string(), v.to_string());
        }
        Invocation {
            path: path.iter().map(|s| s.to_string()).collect(),
            args: args.iter().map(|s| s.to_string()).collect(),
            flags: flag_map,
            door,
        }
    }

    #[test]
    fn every_registered_command_carries_json_in_registration_order() {
        let mut r = Registry::new();
        register(&mut r);
        let paths: Vec<String> = r.commands().map(|c| c.dotted()).collect();
        assert_eq!(
            paths,
            vec![
                "secrets.serve",
                "secrets.exec",
                "secrets.add",
                "secrets.rm",
                "secrets.grant",
                "secrets.revoke",
                "secrets.enroll",
                "secrets.put",
                "secrets.set-totp",
                "secrets.automate",
                "secrets.expose",
                "secrets.pending",
                "secrets.approve",
                "secrets.dismiss",
                "secrets.watch",
                "secrets.migrate",
                "secrets.allow-remote-origin",
            ]
        );
        for c in r.commands() {
            assert!(c.flags.iter().any(|f| f.name == "json"), "{} missing --json", c.dotted());
        }
    }

    #[test]
    fn serve_exec_and_enroll_are_cli_only_elsewhere_a_door_hint() {
        let serve = inv(Door::Mcp, &["secrets", "serve"], &[], &[]);
        assert_eq!(handle_secrets_serve(&serve).status, Status::Usage);
        let exec = inv(Door::A2a, &["secrets", "exec"], &[], &[]);
        assert_eq!(handle_secrets_exec(&exec).status, Status::Usage);
        let enroll = inv(Door::Daemon, &["secrets", "enroll"], &[], &[]);
        assert_eq!(handle_secrets_enroll(&enroll).status, Status::Usage);

        let serve_cli = inv(Door::Cli, &["secrets", "serve"], &[], &[]);
        assert_eq!(handle_secrets_serve(&serve_cli).status, Status::Ok);
        let exec_cli = inv(Door::Cli, &["secrets", "exec"], &[], &[]);
        assert_eq!(handle_secrets_exec(&exec_cli).status, Status::Ok);
        let enroll_cli = inv(Door::Cli, &["secrets", "enroll"], &[], &[]);
        assert_eq!(handle_secrets_enroll(&enroll_cli).status, Status::Ok);
    }

    /// `watch` (this commit) is special-cased the same way — CLI-only, same
    /// door-hint shape, no admin-identity check (it touches no
    /// `policy.json`, only the socket-side operator surface `pending`/
    /// `approve`/`dismiss` already draw).
    #[test]
    fn watch_is_cli_only_elsewhere_a_door_hint() {
        let watch = inv(Door::Mcp, &["secrets", "watch"], &[], &[]);
        assert_eq!(handle_secrets_watch(&watch).status, Status::Usage);
        let watch_cli = inv(Door::Cli, &["secrets", "watch"], &[], &[]);
        assert_eq!(handle_secrets_watch(&watch_cli).status, Status::Ok);
    }

    /// `--popup`+`--json` (tracker #71 Part 2, this commit): the two modes
    /// both own "how a parked ask gets completed" and can't both drive it —
    /// refused as a usage error before `watch::run` is ever reached.
    /// `--popup` alone, or `--json` alone, are both still fine.
    #[test]
    fn watch_refuses_popup_and_json_together_as_a_usage_error() {
        let both = inv(Door::Cli, &["secrets", "watch"], &[], &[("popup", "true"), ("json", "true")]);
        let out = handle_secrets_watch(&both);
        assert_eq!(out.status, Status::Usage);
        assert!(out.message.contains("--popup") && out.message.contains("--json"), "{}", out.message);

        let popup_only = inv(Door::Cli, &["secrets", "watch"], &[], &[("popup", "true")]);
        assert_eq!(handle_secrets_watch(&popup_only).status, Status::Ok);

        let json_only = inv(Door::Cli, &["secrets", "watch"], &[], &[("json", "true")]);
        assert_eq!(handle_secrets_watch(&json_only).status, Status::Ok);
    }

    #[test]
    fn add_then_rm_round_trips_through_policy_json() {
        with_secrets_home("add-rm", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            let out = handle_secrets_add(&add);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert_eq!(store::load_policies(home).unwrap().len(), 1);

            // Duplicate add is an error, not a silent overwrite.
            let dup = handle_secrets_add(&add);
            assert_eq!(dup.status, Status::Error);

            let rm = inv(Door::Cli, &["secrets", "rm"], &["t"], &[]);
            let out = handle_secrets_rm(&rm);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(store::load_policies(home).unwrap().is_empty());

            // Removing again (nothing left) is an error.
            assert_eq!(handle_secrets_rm(&rm).status, Status::Error);
        });
    }

    #[test]
    fn add_rejects_an_invalid_secret_name() {
        with_secrets_home("badname", |_home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["Bad--Name"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Usage);
        });
    }

    #[test]
    fn add_requires_key_but_not_backend() {
        with_secrets_home("missingflags", |_home| {
            let no_key = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass")]);
            assert_eq!(handle_secrets_add(&no_key).status, Status::Usage);
        });
    }

    /// P-G1 (task #70), DEFAULT FLIP: `secrets add` with no `--backend`
    /// now records `age` (was `file` in spirit, never actually a code
    /// default before this — `--backend` used to be a hard requirement).
    #[test]
    fn add_defaults_backend_to_age_when_backend_flag_is_omitted() {
        with_secrets_home("default-backend", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("key", "x")]);
            let out = handle_secrets_add(&add);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            let policies = store::load_policies(home).unwrap();
            assert_eq!(policies[0].backend, "age");
        });
    }

    /// An EXPLICIT `--backend` still wins over the default — the flip only
    /// changes what happens when the flag is omitted entirely.
    #[test]
    fn add_still_honors_an_explicit_backend() {
        with_secrets_home("explicit-backend", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let policies = store::load_policies(home).unwrap();
            assert_eq!(policies[0].backend, "pass");
        });
    }

    #[test]
    fn add_reads_no_value_only_backend_and_key() {
        with_secrets_home("novalue", |home| {
            let add = inv(
                Door::Cli,
                &["secrets", "add"],
                &["t"],
                &[("backend", "pass"), ("key", "prod/db"), ("consumers", "m, verba")],
            );
            handle_secrets_add(&add);
            let policies = store::load_policies(home).unwrap();
            assert_eq!(policies[0].backend, "pass");
            assert_eq!(policies[0].key, "prod/db");
            assert_eq!(policies[0].consumers, vec!["m".to_string(), "verba".to_string()]);
        });
    }

    #[test]
    fn require_totp_flag_is_recorded() {
        with_secrets_home("requiretotp", |home| {
            let add = inv(
                Door::Cli,
                &["secrets", "add"],
                &["t"],
                &[("backend", "pass"), ("key", "x"), ("require-totp", "true")],
            );
            handle_secrets_add(&add);
            assert!(store::load_policies(home).unwrap()[0].require_totp);
        });
    }

    #[test]
    fn grant_then_revoke_round_trips_the_consumer_list() {
        with_secrets_home("grant-revoke", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);

            let grant = inv(Door::Cli, &["secrets", "grant"], &["t", "m"], &[]);
            assert_eq!(handle_secrets_grant(&grant).status, Status::Ok);
            assert_eq!(store::load_policies(home).unwrap()[0].consumers, vec!["m".to_string()]);

            // Granting the same consumer twice does not duplicate it.
            handle_secrets_grant(&grant);
            assert_eq!(store::load_policies(home).unwrap()[0].consumers.len(), 1);

            let revoke = inv(Door::Cli, &["secrets", "revoke"], &["t", "m"], &[]);
            assert_eq!(handle_secrets_revoke(&revoke).status, Status::Ok);
            assert!(store::load_policies(home).unwrap()[0].consumers.is_empty());
        });
    }

    #[test]
    fn grant_on_an_unknown_secret_is_an_error() {
        with_secrets_home("grant-unknown", |_home| {
            let grant = inv(Door::Cli, &["secrets", "grant"], &["nope", "m"], &[]);
            assert_eq!(handle_secrets_grant(&grant).status, Status::Error);
        });
    }

    /// Bounce-fix item 2 (P-V2 review): the admin quartet is CLI-only. A
    /// non-CLI door must get the door-hint AND must never mutate
    /// `policy.json` — proven here by seeding one existing policy first and
    /// asserting the on-disk list is byte-identical after every gated call
    /// (add would append, rm/grant/revoke would rewrite; none of them may
    /// run at all).
    #[test]
    fn admin_quartet_is_cli_only_a_non_cli_door_never_mutates_policy_json() {
        with_secrets_home("door-gate", |home| {
            let seed = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&seed).status, Status::Ok);
            let before = store::load_policies(home).unwrap();

            for door in [Door::Mcp, Door::A2a, Door::Daemon] {
                let add = inv(door, &["secrets", "add"], &["other"], &[("backend", "pass"), ("key", "y")]);
                assert_eq!(handle_secrets_add(&add).status, Status::Usage, "add over {door:?}");

                let rm = inv(door, &["secrets", "rm"], &["t"], &[]);
                assert_eq!(handle_secrets_rm(&rm).status, Status::Usage, "rm over {door:?}");

                let grant = inv(door, &["secrets", "grant"], &["t", "m"], &[]);
                assert_eq!(handle_secrets_grant(&grant).status, Status::Usage, "grant over {door:?}");

                let revoke = inv(door, &["secrets", "revoke"], &["t", "m"], &[]);
                assert_eq!(handle_secrets_revoke(&revoke).status, Status::Usage, "revoke over {door:?}");

                assert_eq!(store::load_policies(home).unwrap(), before, "policy.json mutated over {door:?}");
            }
        });
    }

    /// `put` (P-V4c) holds the SAME CLI-only discipline as the admin
    /// quartet, proven the same way — `policy.json` byte-identical AND the
    /// backend's on-disk store dir untouched (a gated `put` must never even
    /// REACH `client::run_put`, so it can neither read stdin nor write
    /// through a backend's `set` template).
    #[test]
    fn put_is_cli_only_a_non_cli_door_never_mutates_policy_json_or_the_store_dir() {
        with_secrets_home("put-door-gate", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "file"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            let policies_before = store::load_policies(home).unwrap();

            // A store dir with a pre-existing file, standing in for "a
            // secret already written by an earlier, legitimate put" — a
            // gated attempt must leave it byte-identical.
            let store_dir = home.join("store");
            std::fs::create_dir_all(&store_dir).unwrap();
            std::fs::write(store_dir.join("k"), b"pre-existing-content").unwrap();
            let store_before = std::fs::read(store_dir.join("k")).unwrap();

            for door in [Door::Mcp, Door::A2a, Door::Daemon] {
                let put = inv(door, &["secrets", "put"], &["t"], &[]);
                assert_eq!(handle_secrets_put(&put).status, Status::Usage, "put over {door:?}");
            }

            assert_eq!(store::load_policies(home).unwrap(), policies_before, "policy.json mutated by a gated put");
            assert_eq!(std::fs::read(store_dir.join("k")).unwrap(), store_before, "store dir mutated by a gated put");
        });
    }

    #[test]
    fn put_requires_a_secret_name() {
        with_secrets_home("put-noname", |_home| {
            let put = inv(Door::Cli, &["secrets", "put"], &[], &[]);
            assert_eq!(handle_secrets_put(&put).status, Status::Usage);
        });
    }

    #[test]
    fn put_rejects_an_invalid_secret_name() {
        with_secrets_home("put-badname", |_home| {
            let put = inv(Door::Cli, &["secrets", "put"], &["Bad--Name"], &[]);
            assert_eq!(handle_secrets_put(&put).status, Status::Usage);
        });
    }

    // ── set-totp ─────────────────────────────────────────────────────────

    #[test]
    fn set_totp_flips_on_and_persists_reload_proves() {
        with_secrets_home("set-totp-on", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].require_totp);

            let on = inv(Door::Cli, &["secrets", "set-totp"], &["t", "on"], &[]);
            let out = handle_secrets_set_totp(&on);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(!out.changed.is_empty());

            // Reload proves the write actually landed on disk, not just in
            // the in-memory `Vec` this call happened to mutate.
            assert!(store::load_policies(home).unwrap()[0].require_totp);
        });
    }

    #[test]
    fn set_totp_on_off_on_round_trips() {
        with_secrets_home("set-totp-roundtrip", |home| {
            let add = inv(
                Door::Cli,
                &["secrets", "add"],
                &["t"],
                &[("backend", "pass"), ("key", "x"), ("require-totp", "true")],
            );
            handle_secrets_add(&add);
            assert!(store::load_policies(home).unwrap()[0].require_totp);

            let off = inv(Door::Cli, &["secrets", "set-totp"], &["t", "off"], &[]);
            assert_eq!(handle_secrets_set_totp(&off).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].require_totp);

            let on = inv(Door::Cli, &["secrets", "set-totp"], &["t", "on"], &[]);
            assert_eq!(handle_secrets_set_totp(&on).status, Status::Ok);
            assert!(store::load_policies(home).unwrap()[0].require_totp);

            let off_again = inv(Door::Cli, &["secrets", "set-totp"], &["t", "off"], &[]);
            assert_eq!(handle_secrets_set_totp(&off_again).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].require_totp);
        });
    }

    /// Idempotency (house rule: report exactly what changed) — re-setting
    /// the state a policy already has must report "unchanged" AND must not
    /// even rewrite `policy.json` (proven byte-identical, not merely
    /// value-equal, so a re-touch of the file's mtime/formatting would also
    /// be caught).
    #[test]
    fn set_totp_re_setting_the_same_state_is_a_reported_no_op() {
        with_secrets_home("set-totp-idempotent", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let bytes_before = std::fs::read(store::policy_path(home)).unwrap();

            let off = inv(Door::Cli, &["secrets", "set-totp"], &["t", "off"], &[]);
            let out = handle_secrets_set_totp(&off);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.changed.is_empty(), "a no-op set-totp must report nothing changed");
            assert!(out.message.contains("unchanged"), "{}", out.message);

            let bytes_after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(bytes_before, bytes_after, "a no-op set-totp must not even rewrite policy.json");
        });
    }

    #[test]
    fn set_totp_on_an_unknown_secret_is_a_clean_error() {
        with_secrets_home("set-totp-unknown", |_home| {
            let set = inv(Door::Cli, &["secrets", "set-totp"], &["nope", "on"], &[]);
            let out = handle_secrets_set_totp(&set);
            assert_eq!(out.status, Status::Error);
            assert!(out.message.contains("no policy"), "{}", out.message);
        });
    }

    #[test]
    fn set_totp_rejects_a_state_that_is_not_on_or_off() {
        with_secrets_home("set-totp-badstate", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let bogus = inv(Door::Cli, &["secrets", "set-totp"], &["t", "maybe"], &[]);
            assert_eq!(handle_secrets_set_totp(&bogus).status, Status::Usage);
            // A rejected state must not touch the file either.
            assert!(!store::load_policies(home).unwrap()[0].require_totp);
        });
    }

    /// Same CLI-only discipline as the rest of the admin surface (module
    /// doc), proven the same way as `admin_quartet_is_cli_only_...`:
    /// `policy.json` byte-identical after every gated attempt over every
    /// non-CLI door.
    #[test]
    fn set_totp_is_cli_only_a_non_cli_door_never_mutates_policy_json() {
        with_secrets_home("set-totp-door-gate", |home| {
            let seed = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&seed).status, Status::Ok);
            let before = std::fs::read(store::policy_path(home)).unwrap();

            for door in [Door::Mcp, Door::A2a, Door::Daemon] {
                let set = inv(door, &["secrets", "set-totp"], &["t", "on"], &[]);
                assert_eq!(handle_secrets_set_totp(&set).status, Status::Usage, "set-totp over {door:?}");
            }

            let after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(before, after, "policy.json mutated by a gated set-totp");
        });
    }

    /// The deliverable's own end-to-end proof: `add --require-totp` births
    /// a policy that is genuinely unresolvable without a code, not merely
    /// one whose `require_totp` field happens to read `true` on disk — a
    /// REAL broker + socket round trip, the same shape as `tests/e2e.rs`'s
    /// own requireTotp coverage, but seeded through the actual CLI handler
    /// under test here rather than a hand-built `Policy`.
    #[test]
    fn require_totp_on_add_births_a_gated_policy_denied_without_a_code() {
        with_secrets_home("require-totp-add-e2e", |home| {
            let add = inv(
                Door::Cli,
                &["secrets", "add"],
                &["locked"],
                &[("backend", "pass"), ("key", "x"), ("require-totp", "true")],
            );
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            assert!(store::load_policies(home).unwrap()[0].require_totp);

            // A short /tmp-direct socket path — sockaddr_un's ~108-byte
            // sun_path can overflow under a nested tempdir (the same SUN_LEN
            // caution `tests/e2e.rs`'s own `short_tmp` documents).
            let socket_path = std::path::PathBuf::from(format!(
                "/tmp/aoide-secrets-cmd-totp-{}-{}.sock",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            ));

            let home_for_thread = home.to_path_buf();
            let sock_for_thread = socket_path.clone();
            let broker_thread = std::thread::spawn(move || {
                let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
            });

            let mut connected = false;
            for _ in 0..50 {
                if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                    connected = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(connected, "broker did not bind {} in time", socket_path.display());

            let err = crate::client::resolve(&socket_path, "locked", "m", None, None, None).unwrap_err();
            assert!(err.contains("no TOTP enrollment"), "{err}");

            drop(broker_thread);
            std::fs::remove_file(&socket_path).ok();
        });
    }

    // ── policy.json I/O errors get the poisoned-file diagnosis ─────────────

    /// End-to-end proof that `policy_io_error` is actually wired into the
    /// admin quintet's call sites, not merely unit-tested in isolation on
    /// `home.rs`'s side: a `policy.json` this process's own euid cannot
    /// read (mode `0000`, still owned by the SAME euid that owns the
    /// secrets home — the euid guard passes, exactly the "even though the
    /// euid guard passed" case the task describes) must surface the
    /// `chown --reference=` hint through the real `Outcome`, not the old
    /// bare `format!("policy.json: {e}")`. Skipped under a root test
    /// runner (root reads `0000` files fine, so the denial this test
    /// depends on wouldn't happen).
    #[test]
    fn a_policy_json_this_euid_cannot_read_gets_the_chown_reference_hint() {
        if home::effective_uid() == 0 {
            return;
        }
        with_secrets_home("poisoned", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);

            use std::os::unix::fs::PermissionsExt;
            let path = store::policy_path(home);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

            let rm = inv(Door::Cli, &["secrets", "rm"], &["t"], &[]);
            let out = handle_secrets_rm(&rm);

            // Restore before any assertion could early-return and leave the
            // tempdir's cleanup unable to remove an unreadable file.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

            assert_eq!(out.status, Status::Error, "{out:?}");
            assert!(out.message.to_lowercase().contains("permission denied"), "{}", out.message);
            assert!(out.message.contains("chown --reference="), "{}", out.message);
            assert!(out.message.contains(&path.display().to_string()), "{}", out.message);
        });
    }

    // ── enroll --show / --force conflict ────────────────────────────────

    #[test]
    fn enroll_show_and_force_together_is_a_usage_error() {
        let both = inv(Door::Cli, &["secrets", "enroll"], &[], &[("force", "true"), ("show", "true")]);
        assert_eq!(handle_secrets_enroll(&both).status, Status::Usage);

        let show_only = inv(Door::Cli, &["secrets", "enroll"], &[], &[("show", "true")]);
        assert_eq!(handle_secrets_enroll(&show_only).status, Status::Ok);

        let force_only = inv(Door::Cli, &["secrets", "enroll"], &[], &[("force", "true")]);
        assert_eq!(handle_secrets_enroll(&force_only).status, Status::Ok);
    }

    // ── automate (P-N1) ──────────────────────────────────────────────────

    #[test]
    fn automate_on_off_flips_automation_enabled_and_persists_reload_proves() {
        with_secrets_home("automate-on-off", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].automation.enabled);

            let on = inv(Door::Cli, &["secrets", "automate"], &["t", "on"], &[]);
            let out = handle_secrets_automate(&on);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(!out.changed.is_empty());
            assert!(store::load_policies(home).unwrap()[0].automation.enabled);

            let off = inv(Door::Cli, &["secrets", "automate"], &["t", "off"], &[]);
            assert_eq!(handle_secrets_automate(&off).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].automation.enabled);
        });
    }

    // ── allow-remote-origin (LANE IDENTITY P-ID4) ────────────────────────

    #[test]
    fn allow_remote_origin_on_off_flips_the_bit_and_persists_reload_proves() {
        with_secrets_home("aro-on-off", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            assert!(
                !store::load_policies(home).unwrap()[0].allow_remote_origin,
                "a fresh policy denies remote-origin callers — the default"
            );

            let on = inv(Door::Cli, &["secrets", "allow-remote-origin"], &["t", "on"], &[]);
            let out = handle_secrets_allow_remote_origin(&on);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(!out.changed.is_empty());
            assert!(out.message.contains("allowRemoteOrigin"), "{}", out.message);
            assert!(store::load_policies(home).unwrap()[0].allow_remote_origin);

            let off = inv(Door::Cli, &["secrets", "allow-remote-origin"], &["t", "off"], &[]);
            assert_eq!(handle_secrets_allow_remote_origin(&off).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].allow_remote_origin);
        });
    }

    #[test]
    fn allow_remote_origin_re_set_is_a_reported_no_op() {
        with_secrets_home("aro-idempotent", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let on = inv(Door::Cli, &["secrets", "allow-remote-origin"], &["t", "on"], &[]);
            handle_secrets_allow_remote_origin(&on);
            let bytes_before = std::fs::read(store::policy_path(home)).unwrap();

            let out = handle_secrets_allow_remote_origin(&on);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.changed.is_empty(), "a no-op allow-remote-origin must report nothing changed");
            assert!(out.message.contains("unchanged"), "{}", out.message);
            assert_eq!(
                std::fs::read(store::policy_path(home)).unwrap(),
                bytes_before,
                "a no-op must not rewrite policy.json"
            );
        });
    }

    #[test]
    fn allow_remote_origin_usage_errors_teach_the_exact_spelling() {
        with_secrets_home("aro-usage", |_home| {
            let missing_state = inv(Door::Cli, &["secrets", "allow-remote-origin"], &["t"], &[]);
            let out = handle_secrets_allow_remote_origin(&missing_state);
            assert_eq!(out.status, Status::Usage);
            assert!(out.message.contains("on|off"), "{}", out.message);

            let bad_state = inv(Door::Cli, &["secrets", "allow-remote-origin"], &["t", "maybe"], &[]);
            let out = handle_secrets_allow_remote_origin(&bad_state);
            assert_eq!(out.status, Status::Usage);
            assert!(out.message.contains("`maybe`"), "{}", out.message);

            let unknown = inv(Door::Cli, &["secrets", "allow-remote-origin"], &["nope", "on"], &[]);
            let out = handle_secrets_allow_remote_origin(&unknown);
            assert_eq!(out.status, Status::Error);
            assert!(out.message.contains("no policy for secret `nope`"), "{}", out.message);
        });
    }

    #[test]
    fn automate_on_re_set_is_a_reported_no_op() {
        with_secrets_home("automate-idempotent", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let on = inv(Door::Cli, &["secrets", "automate"], &["t", "on"], &[]);
            handle_secrets_automate(&on);
            let bytes_before = std::fs::read(store::policy_path(home)).unwrap();

            let out = handle_secrets_automate(&on);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.changed.is_empty(), "a no-op automate on|off must report nothing changed");
            assert!(out.message.contains("unchanged"), "{}", out.message);

            let bytes_after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(bytes_before, bytes_after, "a no-op automate must not even rewrite policy.json");
        });
    }

    #[test]
    fn automate_grant_then_revoke_round_trips_automation_consumers() {
        with_secrets_home("automate-grant-revoke", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);

            let grant = inv(Door::Cli, &["secrets", "automate"], &["t", "grant", "m"], &[]);
            let out = handle_secrets_automate(&grant);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(!out.changed.is_empty());
            assert_eq!(store::load_policies(home).unwrap()[0].automation.consumers, vec!["m".to_string()]);

            let revoke = inv(Door::Cli, &["secrets", "automate"], &["t", "revoke", "m"], &[]);
            assert_eq!(handle_secrets_automate(&revoke).status, Status::Ok);
            assert!(store::load_policies(home).unwrap()[0].automation.consumers.is_empty());
        });
    }

    #[test]
    fn automate_grant_on_an_already_listed_consumer_is_a_reported_no_op() {
        with_secrets_home("automate-grant-idempotent", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let grant = inv(Door::Cli, &["secrets", "automate"], &["t", "grant", "m"], &[]);
            handle_secrets_automate(&grant);
            let bytes_before = std::fs::read(store::policy_path(home)).unwrap();

            let out = handle_secrets_automate(&grant);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.changed.is_empty(), "granting an already-listed consumer must report nothing changed");
            assert!(out.message.contains("unchanged"), "{}", out.message);

            let bytes_after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(bytes_before, bytes_after);
        });
    }

    #[test]
    fn automate_revoke_on_an_absent_consumer_is_a_reported_no_op() {
        with_secrets_home("automate-revoke-idempotent", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let bytes_before = std::fs::read(store::policy_path(home)).unwrap();

            let revoke = inv(Door::Cli, &["secrets", "automate"], &["t", "revoke", "m"], &[]);
            let out = handle_secrets_automate(&revoke);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.changed.is_empty(), "revoking an absent consumer must report nothing changed");
            assert!(out.message.contains("unchanged"), "{}", out.message);

            let bytes_after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(bytes_before, bytes_after);
        });
    }

    #[test]
    fn automate_grant_rejects_an_invalid_consumer_name() {
        with_secrets_home("automate-grant-badname", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let grant = inv(Door::Cli, &["secrets", "automate"], &["t", "grant", "Bad--Name"], &[]);
            assert_eq!(handle_secrets_automate(&grant).status, Status::Usage);
            assert!(store::load_policies(home).unwrap()[0].automation.consumers.is_empty());
        });
    }

    #[test]
    fn automate_rejects_an_action_that_is_not_on_off_grant_or_revoke() {
        with_secrets_home("automate-badaction", |_home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let bogus = inv(Door::Cli, &["secrets", "automate"], &["t", "maybe"], &[]);
            assert_eq!(handle_secrets_automate(&bogus).status, Status::Usage);
        });
    }

    #[test]
    fn automate_grant_without_a_consumer_is_a_usage_error() {
        with_secrets_home("automate-grant-noconsumer", |_home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let grant = inv(Door::Cli, &["secrets", "automate"], &["t", "grant"], &[]);
            assert_eq!(handle_secrets_automate(&grant).status, Status::Usage);
        });
    }

    #[test]
    fn automate_on_an_unknown_secret_is_a_clean_error() {
        with_secrets_home("automate-unknown", |_home| {
            let on = inv(Door::Cli, &["secrets", "automate"], &["nope", "on"], &[]);
            assert_eq!(handle_secrets_automate(&on).status, Status::Error);
        });
    }

    #[test]
    fn automate_is_cli_only_a_non_cli_door_never_mutates_policy_json() {
        with_secrets_home("automate-door-gate", |home| {
            let seed = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&seed).status, Status::Ok);
            let before = std::fs::read(store::policy_path(home)).unwrap();

            for door in [Door::Mcp, Door::A2a, Door::Daemon] {
                let on = inv(door, &["secrets", "automate"], &["t", "on"], &[]);
                assert_eq!(handle_secrets_automate(&on).status, Status::Usage, "automate over {door:?}");
            }

            let after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(before, after, "policy.json mutated by a gated automate");
        });
    }

    // ── expose (P-N1) ────────────────────────────────────────────────────

    #[test]
    fn expose_on_off_flips_remote_and_persists_reload_proves() {
        with_secrets_home("expose-on-off", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].remote);

            let on = inv(Door::Cli, &["secrets", "expose"], &["t", "on"], &[]);
            let out = handle_secrets_expose(&on);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(!out.changed.is_empty());
            assert!(store::load_policies(home).unwrap()[0].remote);

            let off = inv(Door::Cli, &["secrets", "expose"], &["t", "off"], &[]);
            assert_eq!(handle_secrets_expose(&off).status, Status::Ok);
            assert!(!store::load_policies(home).unwrap()[0].remote);
        });
    }

    #[test]
    fn expose_re_setting_the_same_state_is_a_reported_no_op() {
        with_secrets_home("expose-idempotent", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let bytes_before = std::fs::read(store::policy_path(home)).unwrap();

            let off = inv(Door::Cli, &["secrets", "expose"], &["t", "off"], &[]);
            let out = handle_secrets_expose(&off);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.changed.is_empty(), "a no-op expose must report nothing changed");
            assert!(out.message.contains("unchanged"), "{}", out.message);

            let bytes_after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(bytes_before, bytes_after, "a no-op expose must not even rewrite policy.json");
        });
    }

    #[test]
    fn expose_on_an_unknown_secret_is_a_clean_error() {
        with_secrets_home("expose-unknown", |_home| {
            let on = inv(Door::Cli, &["secrets", "expose"], &["nope", "on"], &[]);
            assert_eq!(handle_secrets_expose(&on).status, Status::Error);
        });
    }

    #[test]
    fn expose_rejects_a_state_that_is_not_on_or_off() {
        with_secrets_home("expose-badstate", |home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            handle_secrets_add(&add);
            let bogus = inv(Door::Cli, &["secrets", "expose"], &["t", "maybe"], &[]);
            assert_eq!(handle_secrets_expose(&bogus).status, Status::Usage);
            assert!(!store::load_policies(home).unwrap()[0].remote);
        });
    }

    #[test]
    fn expose_is_cli_only_a_non_cli_door_never_mutates_policy_json() {
        with_secrets_home("expose-door-gate", |home| {
            let seed = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            assert_eq!(handle_secrets_add(&seed).status, Status::Ok);
            let before = std::fs::read(store::policy_path(home)).unwrap();

            for door in [Door::Mcp, Door::A2a, Door::Daemon] {
                let on = inv(door, &["secrets", "expose"], &["t", "on"], &[]);
                assert_eq!(handle_secrets_expose(&on).status, Status::Usage, "expose over {door:?}");
            }

            let after = std::fs::read(store::policy_path(home)).unwrap();
            assert_eq!(before, after, "policy.json mutated by a gated expose");
        });
    }

    /// The euid guard applies to the new commands (task requirement): `/` is
    /// stat-able on every Linux host and, on any non-root test runner, is
    /// owned by a DIFFERENT uid than this process's own euid — a real
    /// mismatch, not an injected one, proving `require_admin_identity` is
    /// actually wired into both new handlers, not merely present in
    /// `home.rs`'s own pure unit tests. Skipped under a root test runner
    /// (root would own `/` too, so the mismatch this test depends on
    /// wouldn't exist).
    #[test]
    fn automate_and_expose_refuse_a_mismatched_euid_before_touching_policy_json() {
        if home::effective_uid() == 0 {
            return;
        }
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::set_var("AOIDE_SECRETS_HOME", "/");
        // Task #79: guarantee the `NoSocket` fallback branch (`with_secrets_
        // home`'s own doc, same reasoning — this test doesn't use that
        // fixture since it needs `AOIDE_SECRETS_HOME` pinned to `/`, not a
        // fresh tempdir, but the real-broker hazard is identical).
        let saved_socket = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        std::env::set_var("AOIDE_SECRETS_SOCKET", "/nonexistent/aoide-secrets-test/no-such-broker.sock");

        let automate = inv(Door::Cli, &["secrets", "automate"], &["t", "on"], &[]);
        let out = handle_secrets_automate(&automate);
        assert_eq!(out.status, Status::Error, "{out:?}");
        assert!(out.message.contains("must run as the broker user"), "{}", out.message);

        let expose = inv(Door::Cli, &["secrets", "expose"], &["t", "on"], &[]);
        let out = handle_secrets_expose(&expose);
        assert_eq!(out.status, Status::Error, "{out:?}");
        assert!(out.message.contains("must run as the broker user"), "{}", out.message);

        match saved_socket {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }

    // ── secrets migrate (P-G2, task #72) ────────────────────────────────

    /// Feature-detects a real `age`/`age-keygen` on `PATH`, mirroring
    /// `backend::tests::age_tools_available` (each module's own `#[cfg(test)]`
    /// block, `AGENTS.md`'s "I/O is confined to seven named modules"
    /// invariant — test helpers are not shared across modules here). Any
    /// migrate test that migrates ONTO the built-in `age` backend (needing
    /// a real identity mint) skips cleanly, with a printed reason, rather
    /// than panicking (and poisoning `env_lock` for every other test in
    /// this process) when this host has no `age` on `PATH`.
    fn age_tools_available() -> bool {
        let age_keygen = std::process::Command::new("age-keygen").arg("--version").output();
        let age = std::process::Command::new("age").arg("--version").output();
        matches!(age_keygen, Ok(o) if o.status.code().is_some()) && matches!(age, Ok(o) if o.status.code().is_some())
    }

    #[test]
    fn migrate_moves_the_value_flips_the_policy_and_removes_the_old_builtin_value() {
        if !age_tools_available() {
            eprintln!("skipping migrate_moves_the_value_flips_the_policy_and_removes_the_old_builtin_value: age/age-keygen not found on PATH");
            return;
        }
        with_secrets_home("migrate-happy-path", |home| {
            crate::backend::seed_default_backends(home).unwrap();
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "file"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            crate::backend::store_value(home, "file", "k", "the-value").unwrap();
            assert!(home.join("store").join("k").exists());

            let migrate = inv(Door::Cli, &["secrets", "migrate"], &["t"], &[]);
            let out = handle_secrets_migrate(&migrate);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.message.contains("old value removed"), "{}", out.message);

            let policies = store::load_policies(home).unwrap();
            assert_eq!(policies[0].backend, "age", "policy must be flipped to the default target `age`");

            assert_eq!(crate::backend::fetch_value(home, "age", "k").unwrap(), "the-value");
            assert!(!home.join("store").join("k").exists(), "old file-backend value must be removed");
        });
    }

    /// Judge fix, this commit: a migrate onto `age` must warn that
    /// `age.key` is now the ONLY decryptor of the moved value, right in the
    /// success message — an operator backing up `values/` alone (a natural
    /// instinct, that's where the ciphertext lives) needs to see this
    /// before discovering the gap the hard way. A migrate that does NOT
    /// land on `age` (source `age` -> target `file` here) must not carry
    /// this note at all — it isn't the backend this migrate just moved the
    /// value onto.
    #[test]
    fn migrate_onto_age_warns_that_age_key_is_now_the_only_decryptor() {
        if !age_tools_available() {
            eprintln!("skipping migrate_onto_age_warns_that_age_key_is_now_the_only_decryptor: age/age-keygen not found on PATH");
            return;
        }
        with_secrets_home("migrate-key-lifecycle-onto-age", |home| {
            crate::backend::seed_default_backends(home).unwrap();
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "file"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            crate::backend::store_value(home, "file", "k", "the-value").unwrap();

            let migrate = inv(Door::Cli, &["secrets", "migrate"], &["t"], &[("backend", "age")]);
            let out = handle_secrets_migrate(&migrate);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(
                out.message.contains("age.key is now the ONLY decryptor"),
                "migrate onto age must warn about the key-lifecycle risk: {}",
                out.message
            );
        });

        with_secrets_home("migrate-key-lifecycle-off-age", |home| {
            crate::backend::seed_default_backends(home).unwrap();
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "age"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            crate::backend::mint_age_identity_if_needed(home).unwrap();
            crate::backend::store_value(home, "age", "k", "the-value").unwrap();

            let migrate = inv(Door::Cli, &["secrets", "migrate"], &["t"], &[("backend", "file")]);
            let out = handle_secrets_migrate(&migrate);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(
                !out.message.contains("age.key is now the ONLY decryptor"),
                "a migrate that does not land on age must not carry the age-specific note: {}",
                out.message
            );
        });
    }

    #[test]
    fn migrate_to_the_same_backend_is_an_idempotent_no_op() {
        with_secrets_home("migrate-noop", |home| {
            crate::backend::seed_default_backends(home).unwrap();
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "age"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            let before = store::load_policies(home).unwrap();

            let migrate = inv(Door::Cli, &["secrets", "migrate"], &["t"], &[("backend", "age")]);
            let out = handle_secrets_migrate(&migrate);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.message.contains("unchanged"), "{}", out.message);
            assert!(out.changed.is_empty(), "a same-backend migrate must not report anything changed");

            assert_eq!(store::load_policies(home).unwrap(), before, "a no-op migrate must not rewrite policy.json");
        });
    }

    #[test]
    fn migrate_with_no_stored_value_under_the_source_is_a_clean_refusal() {
        with_secrets_home("migrate-missing-value", |home| {
            crate::backend::seed_default_backends(home).unwrap();
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "file"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            let before = store::load_policies(home).unwrap();

            // No `store_value` call — the source backend has nothing stored.
            let migrate = inv(Door::Cli, &["secrets", "migrate"], &["t"], &[("backend", "age")]);
            let out = handle_secrets_migrate(&migrate);
            assert_eq!(out.status, Status::Error, "{out:?}");

            assert_eq!(store::load_policies(home).unwrap(), before, "a refused migrate must not touch policy.json");
            assert!(!home.join("values").join("k.age").exists(), "nothing must be stored on the target either");
        });
    }

    #[test]
    fn migrate_on_an_unknown_secret_is_an_error() {
        with_secrets_home("migrate-unknown", |_home| {
            let migrate = inv(Door::Cli, &["secrets", "migrate"], &["nope"], &[]);
            assert_eq!(handle_secrets_migrate(&migrate).status, Status::Error);
        });
    }

    /// A source backend this crate has no built-in path for (a doc preset
    /// like `pass`, or any operator-custom entry) is left completely
    /// untouched — the migrate still succeeds (the value is safely on the
    /// target), but the success message says the old value was left in
    /// place rather than silently doing nothing.
    #[test]
    fn migrate_from_a_non_builtin_source_leaves_the_old_value_alone_and_says_so() {
        if !age_tools_available() {
            eprintln!("skipping migrate_from_a_non_builtin_source_leaves_the_old_value_alone_and_says_so: age/age-keygen not found on PATH");
            return;
        }
        with_secrets_home("migrate-nonbuiltin-source", |home| {
            crate::backend::seed_default_backends(home).unwrap();
            // Add a custom "scratch" backend beside the seeded built-ins,
            // holding the value `secrets add` never touches.
            let doc = serde_json::json!({
                "file": {"get": "cat {home}/store/{name}", "set": "mkdir -p -m 0700 {home}/store && install -m 0600 /dev/stdin {home}/store/{name}"},
                "age": {"get": "age -d -i {home}/age.key {home}/values/{name}.age", "set": "mkdir -p -m 0700 {home}/values && age -e -R {home}/age.recipient -o {home}/values/{name}.age && chmod 0600 {home}/values/{name}.age"},
                "scratch": {"get": "cat {home}/scratch-k", "set": "cat > {home}/scratch-k"},
            });
            std::fs::write(home.join("backends.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
            crate::backend::store_value(home, "scratch", "k", "scratch-value").unwrap();

            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "scratch"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);

            let migrate = inv(Door::Cli, &["secrets", "migrate"], &["t"], &[("backend", "age")]);
            let out = handle_secrets_migrate(&migrate);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert!(out.message.contains("not a built-in backend"), "{}", out.message);

            assert_eq!(crate::backend::fetch_value(home, "age", "k").unwrap(), "scratch-value");
            // The scratch backend's own file is untouched.
            assert!(home.join("scratch-k").exists());
        });
    }

    /// Same discipline as `automate`/`expose` above: an admin-identity
    /// mismatch refuses BEFORE `policy.json` is ever touched.
    #[test]
    fn migrate_refuses_a_mismatched_euid_before_touching_policy_json() {
        if home::effective_uid() == 0 {
            return;
        }
        let _guard = crate::env_lock().lock().unwrap();
        let saved = std::env::var("AOIDE_SECRETS_HOME").ok();
        std::env::set_var("AOIDE_SECRETS_HOME", "/");
        // Task #79: same real-broker hazard as `automate_and_expose_refuse_
        // a_mismatched_euid_before_touching_policy_json` above — pin the
        // socket to a guaranteed-absent path.
        let saved_socket = std::env::var("AOIDE_SECRETS_SOCKET").ok();
        std::env::set_var("AOIDE_SECRETS_SOCKET", "/nonexistent/aoide-secrets-test/no-such-broker.sock");

        let migrate = inv(Door::Cli, &["secrets", "migrate"], &["t"], &[]);
        let out = handle_secrets_migrate(&migrate);
        assert_eq!(out.status, Status::Error, "{out:?}");
        assert!(out.message.contains("must run as the broker user"), "{}", out.message);

        match saved_socket {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
        match saved {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
    }

    // ── task #79: socket-first admin dispatch ───────────────────────────

    /// Task #79 item 6c (fallback path fires when no socket exists): every
    /// `with_secrets_home` test already exercises this branch implicitly
    /// (its own doc — `AOIDE_SECRETS_SOCKET` is pinned to a guaranteed-
    /// absent path), but this test makes the CONTRACT explicit — `add`
    /// reports `path: "direct"` in its `Outcome::data`, not merely "it
    /// worked somehow".
    #[test]
    fn add_falls_back_to_the_direct_write_path_and_reports_it_when_no_socket_is_listening() {
        with_secrets_home("fallback-reports-direct", |_home| {
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass"), ("key", "x")]);
            let out = handle_secrets_add(&add);
            assert_eq!(out.status, Status::Ok, "{out:?}");
            assert_eq!(out.data, Some(json!({"path": "direct"})), "{out:?}");
        });
    }

    /// Task #79 item 6a/1 (broker path taken when the daemon IS listening):
    /// a REAL `broker::serve` bound to a scratch home + socket (the exact
    /// pattern `tests/e2e.rs` already establishes for a real broker), with
    /// `AOIDE_SECRETS_SOCKET` pointed at it and `AOIDE_SECRETS_HOME` left
    /// somewhere ELSE entirely — proving the mutation landed via the
    /// SOCKET (the broker's own home), not a direct write that happened to
    /// share a path by coincidence. A real socket connection in-process
    /// reports THIS test process's own euid on both ends, which is exactly
    /// `broker::admin_gate`'s happy path (same reasoning as `broker.rs`'s
    /// own `admin_add_over_a_real_socket_connection_round_trips_into_
    /// policy_json`).
    #[test]
    fn add_over_a_real_broker_socket_takes_the_broker_path_and_lands_in_the_brokers_own_home() {
        let _guard = crate::env_lock().lock().unwrap();
        let saved_home = std::env::var("AOIDE_SECRETS_HOME").ok();
        let saved_socket = std::env::var("AOIDE_SECRETS_SOCKET").ok();

        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        let broker_home = std::path::PathBuf::from(format!("/tmp/av-cmdadmin-home-{}-{nanos}", std::process::id()));
        let socket_path = std::path::PathBuf::from(format!("/tmp/av-cmdadmin-{}-{nanos}.sock", std::process::id()));
        std::fs::create_dir_all(&broker_home).unwrap();

        let home_for_thread = broker_home.clone();
        let sock_for_thread = socket_path.clone();
        let _broker_thread = std::thread::spawn(move || {
            let _ = crate::broker::serve(&home_for_thread, &sock_for_thread);
        });
        let mut connected = false;
        for _ in 0..50 {
            if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(connected, "broker did not bind {} in time", socket_path.display());

        std::env::set_var("AOIDE_SECRETS_SOCKET", &socket_path);
        std::env::remove_var("AOIDE_SECRETS_HOME");

        let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "scratch"), ("key", "k")]);
        let out = handle_secrets_add(&add);
        assert_eq!(out.status, Status::Ok, "{out:?}");
        assert_eq!(out.data, Some(json!({"path": "broker"})), "{out:?}");

        let policies = store::load_policies(&broker_home).unwrap();
        assert_eq!(policies.len(), 1, "the new policy must have landed in the BROKER's own home");
        assert_eq!(policies[0].name, "t");

        match saved_socket {
            Some(v) => std::env::set_var("AOIDE_SECRETS_SOCKET", v),
            None => std::env::remove_var("AOIDE_SECRETS_SOCKET"),
        }
        match saved_home {
            Some(v) => std::env::set_var("AOIDE_SECRETS_HOME", v),
            None => std::env::remove_var("AOIDE_SECRETS_HOME"),
        }
        std::fs::remove_dir_all(&broker_home).ok();
        std::fs::remove_file(&socket_path).ok();
        // `broker::serve` loops forever accepting connections — detached
        // rather than joined, the same posture `tests/e2e.rs`'s own broker
        // threads already take (module doc precedent there).
    }

    /// Bounce-fix item 2's own discipline (P-V2 review), extended to
    /// `migrate`: CLI-only, and a gated call never mutates `policy.json`.
    #[test]
    fn migrate_is_cli_only_a_non_cli_door_never_mutates_policy_json() {
        with_secrets_home("migrate-door-gate", |home| {
            crate::backend::seed_default_backends(home).unwrap();
            let add = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "file"), ("key", "k")]);
            assert_eq!(handle_secrets_add(&add).status, Status::Ok);
            crate::backend::store_value(home, "file", "k", "the-value").unwrap();
            let before = store::load_policies(home).unwrap();

            for door in [Door::Mcp, Door::A2a, Door::Daemon] {
                let migrate = inv(door, &["secrets", "migrate"], &["t"], &[]);
                assert_eq!(handle_secrets_migrate(&migrate).status, Status::Usage, "migrate over {door:?}");
                assert_eq!(store::load_policies(home).unwrap(), before, "policy.json mutated over {door:?}");
            }
        });
    }
}
