//! `aoide secrets` — the secrets broker's CLI surface (Workstream SECRETS,
//! P-V2, P-V3, P-V4c). Registers EIGHT verbs:
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
//! - `enroll` (P-V3) — CLI-only, special-cased the SAME way as `serve`/
//!   `exec`, for the same reason `exec` is: the printed `otpauth://` URI +
//!   base32 secret must never ride the `Outcome` envelope (this crate's
//!   `AGENTS.md`). [`handle_secrets_enroll`] only gates the door and records
//!   the launch; the actual secret generation/persistence/printing is
//!   `crate::enroll::run`, called from `cli`'s `special` hook.
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
//!   `policy.json`.
//! - `put` (P-V4c) — the write half: `secrets put <name>` reads the value
//!   from STDIN (never argv) and forwards it to the broker's `put` op over
//!   the socket. **NOT special-cased**, unlike `serve`/`exec`/`enroll`:
//!   [`handle_secrets_put`] is a PLAIN handler — CLI-only via the SAME
//!   [`require_cli`] gate as the admin quartet (an agent putting values is
//!   exactly what the design forbids), then it delegates the stdin-read +
//!   socket round trip to `crate::client::run_put`. This differs from
//!   `exec`/`enroll` in the one way that matters: `put`'s wire reply
//!   carries NO value at all (`{"ok":true}` or `{"ok":false,"error":...}`),
//!   and its own success/failure message is name-only
//!   (`format!("put secret \`{name}\`")`) — so nothing about its return
//!   path ever needs to bypass the generic `Outcome` envelope the way a
//!   FETCHED value (`exec`) or a PRINTED secret (`enroll`) would. Appended
//!   LAST in `register()` (golden discipline — `pkgs/aoide/crates/
//!   AGENTS.md`: append, never reorder), golden 59 -> 60.
//!
//! `add`/`rm`/`grant`/`revoke`/`enroll` run AS THE SECRETS USER in deployment
//! (`sudo -u aoide-secrets ...`, wrapped by the nix module at P-V4), but the
//! code itself is uid-agnostic — it only reads/writes whatever
//! `home::secrets_home()` resolves to, same as every other function here.
//! `add` reads NO value at any point: the secrets broker never stores one, only a
//! policy (backend name + key) pointing at where a value can be fetched
//! from later. `put` is the one verb here whose stdin DOES carry a value —
//! it never touches this crate's own storage directly, only the broker's
//! `set` backend template, over the socket (`crate::broker::handle_put`'s
//! module doc).

use crate::home;
use crate::policy::{valid_secret_name, Policy};
use crate::store;
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
        args: [],
        flags: [
            flag!("as", "string", "The consumer name to present to the broker (self-asserted — the policy's consumers[] list is the real gate, not caller identity)."),
            flag!("secret", "string", "The secret's policy name, optionally `name:VAR` to name the injected env var explicitly (default: the name, uppercased, `-` -> `_`)."),
            flag!("totp", "string", "A TOTP code — accepted on the wire, ignored this phase. No enrollment exists yet, so a requireTotp secret is unresolvable regardless (P-V4 wires verification).")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_exec,
        examples: ["secrets exec --as m --secret db-prod -- psql"],
    ));
    r.insert(cmd!(
        path: ["secrets", "add"],
        summary: "Register a new secret's policy: backend + key, never a value (the secrets broker never stores one). No consumers/sharing/TOTP unless given.",
        args: [arg!("name", "string", true, "The secret's nickname.")],
        flags: [
            flag!("backend", "string", "The named backend (backends.json) that fetches this secret's value."),
            flag!("key", "string", "The backend-specific key/identifier substituted into that backend's fetch-command template."),
            flag!("require-totp", "bool", "Require a fresh TOTP code to resolve (P-V2: makes this secret unresolvable until enrollment lands at P-V4)."),
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
        summary: "Enroll this host for TOTP: generate a fresh secret and print its otpauth:// URI + base32 form (plus a QR code when `qrencode` is on PATH). ONE enrollment per host — pass --force to regenerate (old codes stop working immediately). CLI-only: the secret is printed directly to stdout, never through this envelope.",
        args: [],
        flags: [
            flag!("force", "bool", "Regenerate the secret even if one is already enrolled on this host. Invalidates every previously issued code.")
        ],
        gated: false,
        implemented: true,
        handler: handle_secrets_enroll,
        examples: ["secrets enroll", "secrets enroll --force"],
    ));
    r.insert(cmd!(
        path: ["secrets", "put"],
        summary: "Store a value for an EXISTING secret's policy, read from stdin (never argv). CLI-only — no TOTP, since put is admin-side, not agent-facing. The named policy's backend must carry a `set` template (the built-in `file` backend has one by default).",
        args: [arg!("name", "string", true, "The secret's nickname — must already have a policy (`secrets add` first).")],
        flags: [],
        gated: false,
        implemented: true,
        handler: handle_secrets_put,
        examples: ["printf %s hunter2 | aoide secrets put db-prod"],
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
    Outcome::ok(cmd, "enrolling TOTP on this host").with_data(json!({
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
            "secrets policy admin verbs (add/rm/grant/revoke) are CLI-only; run this from a terminal (not over this door)",
        )),
    }
}

fn handle_secrets_add(inv: &Invocation) -> Outcome {
    let cmd = "secrets.add";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, "usage: secrets add <name> --backend <backend> --key <key>");
    };
    if !valid_secret_name(&name) {
        return Outcome::usage(cmd, format!("invalid secret name `{name}`"));
    }
    let Some(backend) = inv.flags.get("backend").cloned() else {
        return Outcome::usage(cmd, "secrets add requires --backend <backend>");
    };
    let Some(key) = inv.flags.get("key").cloned() else {
        return Outcome::usage(cmd, "secrets add requires --key <key>");
    };

    let home = home::secrets_home();
    let mut policies = match store::load_policies(&home) {
        Ok(p) => p,
        Err(e) => return Outcome::error(cmd, format!("policy.json: {e}")),
    };
    if policies.iter().any(|p| p.name == name) {
        return Outcome::error(cmd, format!("secret `{name}` already has a policy — use `secrets rm` first"));
    }

    let mut policy = Policy::new(&name, backend, key);
    policy.require_totp = inv.flag_present("require-totp");
    policy.consumers = inv
        .flags
        .get("consumers")
        .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    policies.push(policy);

    if let Err(e) = store::save_policies(&home, &policies) {
        return Outcome::error(cmd, format!("writing policy.json: {e}"));
    }
    Outcome::ok(cmd, format!("added secret `{name}`")).changed(vec![format!("policy:{name}")])
}

fn handle_secrets_rm(inv: &Invocation) -> Outcome {
    let cmd = "secrets.rm";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, "usage: secrets rm <name>");
    };

    let home = home::secrets_home();
    let mut policies = match store::load_policies(&home) {
        Ok(p) => p,
        Err(e) => return Outcome::error(cmd, format!("policy.json: {e}")),
    };
    let before = policies.len();
    policies.retain(|p| p.name != name);
    if policies.len() == before {
        return Outcome::error(cmd, format!("no policy for secret `{name}`"));
    }

    if let Err(e) = store::save_policies(&home, &policies) {
        return Outcome::error(cmd, format!("writing policy.json: {e}"));
    }
    Outcome::ok(cmd, format!("removed secret `{name}`")).changed(vec![format!("policy:{name}")])
}

/// Shared shape behind `grant`/`revoke`: both take `<name> <consumer>` and
/// differ only in what they do to the `consumers[]` list.
fn edit_consumer(inv: &Invocation, cmd: &str, usage: &str, edit: impl FnOnce(&mut Vec<String>, &str)) -> Outcome {
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, usage);
    };
    let Some(consumer) = inv.args.get(1).cloned() else {
        return Outcome::usage(cmd, usage);
    };

    let home = home::secrets_home();
    let mut policies = match store::load_policies(&home) {
        Ok(p) => p,
        Err(e) => return Outcome::error(cmd, format!("policy.json: {e}")),
    };
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Outcome::error(cmd, format!("no policy for secret `{name}`"));
    };
    edit(&mut policy.consumers, &consumer);

    if let Err(e) = store::save_policies(&home, &policies) {
        return Outcome::error(cmd, format!("writing policy.json: {e}"));
    }
    Outcome::ok(cmd, format!("updated consumers for secret `{name}`")).changed(vec![format!("policy:{name}")])
}

fn handle_secrets_grant(inv: &Invocation) -> Outcome {
    edit_consumer(inv, "secrets.grant", "usage: secrets grant <name> <consumer>", |consumers, consumer| {
        if !consumers.iter().any(|c| c == consumer) {
            consumers.push(consumer.to_string());
        }
    })
}

fn handle_secrets_revoke(inv: &Invocation) -> Outcome {
    edit_consumer(inv, "secrets.revoke", "usage: secrets revoke <name> <consumer>", |consumers, consumer| {
        consumers.retain(|c| c != consumer);
    })
}

/// `secrets put <name>` (P-V4c) — CLI-only via the SAME [`require_cli`]
/// gate as the admin quartet (module doc: an agent putting values is
/// exactly what the design forbids), then a PLAIN delegation to
/// `crate::client::run_put`, which reads the value from stdin and does the
/// socket round trip. The returned [`Outcome`]'s message is name-only —
/// `crate::client::run_put`'s `Result<(), String>` carries no value on
/// either arm (put's own wire reply never has one either), so there is
/// nothing here that could put the value on this envelope even by
/// accident.
fn handle_secrets_put(inv: &Invocation) -> Outcome {
    let cmd = "secrets.put";
    if let Some(hint) = require_cli(inv, cmd) {
        return hint;
    }
    let Some(name) = inv.args.first().cloned() else {
        return Outcome::usage(cmd, "usage: secrets put <name> (value read from stdin)");
    };
    if !valid_secret_name(&name) {
        return Outcome::usage(cmd, format!("invalid secret name `{name}`"));
    }
    match crate::client::run_put(&name, &crate::socket::socket_path()) {
        Ok(()) => Outcome::ok(cmd, format!("put secret `{name}`")),
        Err(e) => Outcome::error(cmd, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let result = f(&dir);
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
    fn add_requires_backend_and_key() {
        with_secrets_home("missingflags", |_home| {
            let no_backend = inv(Door::Cli, &["secrets", "add"], &["t"], &[("key", "x")]);
            assert_eq!(handle_secrets_add(&no_backend).status, Status::Usage);
            let no_key = inv(Door::Cli, &["secrets", "add"], &["t"], &[("backend", "pass")]);
            assert_eq!(handle_secrets_add(&no_key).status, Status::Usage);
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
}
