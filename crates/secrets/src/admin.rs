//! Broker-callable admin-verb mutations (task #79) — the SAME
//! read-modify-write logic `commands.rs`'s direct-home CRUD quintet
//! (`add`/`rm`/`grant`/`revoke`/`set-totp`/`automate`/`expose`/`migrate`)
//! used to carry inline, extracted so `broker::handle_admin` can call it
//! too, inside the SAME `broker::put_lock` critical section a `put` already
//! runs under (module doc — one process, one writer, one lock guarding
//! every `policy.json`/backend-store read-modify-write, admin mutations
//! included as of this phase).
//!
//! Every function here takes a resolved `secrets_home: &Path` and typed,
//! already-validated fields — no `Invocation`, no `Outcome`, no wire `Value`
//! — so the SAME function serves two entirely different callers with two
//! entirely different gates: `commands.rs`'s direct-write fallback (reached
//! only after `require_cli` + `require_admin_identity` already passed) and
//! `broker::handle_admin` (reached only after its own peer-uid-is-the-
//! broker's-own-euid gate already passed, `broker.rs`'s module doc). This
//! module makes NO admin-identity decision of its own — the euid guard
//! belongs entirely to whichever caller is invoking it, matching the
//! `home::admin_identity_check`/`broker::handle_admin` split.
//!
//! **Argument validation (name shape, "on"/"off" spelling, `<name> <consumer>`
//! presence) still lives ONLY in `commands.rs`, never duplicated here.** A
//! wire-side `{op:"admin"}` request that omits a required field, or spells
//! `state`/`action` wrong, gets a plain `Err(String)` from the function
//! below rather than a second parallel usage-error vocabulary — the CLI
//! path's own `Outcome::usage` messages are unreachable from the broker
//! anyway (a malformed admin op is a client bug, not a human mistyping a
//! terminal command), so this module's errors are all "same shape as the
//! CRUD quintet's own domain errors" (`no policy for secret \`x\``, an I/O
//! diagnosis via [`home::describe_home_file_error`]), never a re-derived
//! usage string.
use crate::home;
use crate::policy::Policy;
use crate::store;
use aoide_protocol::Door;
use std::path::Path;

/// A successful admin mutation's report — message text plus the `changed`
/// keys the caller's own envelope (`Outcome::changed`, or the wire reply's
/// `changed` array) should carry. Deliberately NOT `aoide_protocol::output::
/// Outcome` — that type is CLI/dispatch-shaped (`command`, `status`, JSON
/// rendering); this one is the bare fact a mutation reports, read by BOTH
/// `commands.rs` (wraps it into an `Outcome`) and `broker.rs` (wraps it into
/// a wire `Value`).
pub struct AdminOutcome {
    pub message: String,
    pub changed: Vec<String>,
}

impl AdminOutcome {
    fn unchanged(message: impl Into<String>) -> Self {
        Self { message: message.into(), changed: Vec::new() }
    }
    fn changed(message: impl Into<String>, key: String) -> Self {
        Self { message: message.into(), changed: vec![key] }
    }
}

fn policy_io_error(home: &Path, err: std::io::Error) -> String {
    home::describe_home_file_error(home, &store::policy_path(home), &err)
}

/// `secrets add <name> --key <key> [--backend <backend>]` — the same
/// existence check, `Policy::new`, and `requireTotp`/`consumers` seeding
/// `commands::handle_secrets_add` ran inline before this phase.
pub fn add(
    home: &Path,
    name: &str,
    backend: &str,
    key: &str,
    require_totp: bool,
    consumers: Vec<String>,
) -> Result<AdminOutcome, String> {
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    if policies.iter().any(|p| p.name == name) {
        return Err(format!("secret `{name}` already has a policy — use `secrets rm` first"));
    }
    let mut policy = Policy::new(name, backend, key);
    policy.require_totp = require_totp;
    policy.consumers = consumers;
    policies.push(policy);
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;
    Ok(AdminOutcome::changed(format!("added secret `{name}`"), format!("policy:{name}")))
}

/// `secrets rm <name>`.
pub fn rm(home: &Path, name: &str) -> Result<AdminOutcome, String> {
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    let before = policies.len();
    policies.retain(|p| p.name != name);
    if policies.len() == before {
        return Err(format!("no policy for secret `{name}`"));
    }
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;
    Ok(AdminOutcome::changed(format!("removed secret `{name}`"), format!("policy:{name}")))
}

/// Shared shape behind `grant`/`revoke` — mirrors `commands::edit_consumer`'s
/// old inline body exactly, minus the `Invocation`/gate plumbing.
fn edit_consumer(home: &Path, name: &str, consumer: &str, edit: impl FnOnce(&mut Vec<String>, &str)) -> Result<AdminOutcome, String> {
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no policy for secret `{name}`"));
    };
    edit(&mut policy.consumers, consumer);
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;
    Ok(AdminOutcome::changed(format!("updated consumers for secret `{name}`"), format!("policy:{name}")))
}

pub fn grant(home: &Path, name: &str, consumer: &str) -> Result<AdminOutcome, String> {
    edit_consumer(home, name, consumer, |consumers, consumer| {
        if !consumers.iter().any(|c| c == consumer) {
            consumers.push(consumer.to_string());
        }
    })
}

pub fn revoke(home: &Path, name: &str, consumer: &str) -> Result<AdminOutcome, String> {
    edit_consumer(home, name, consumer, |consumers, consumer| {
        consumers.retain(|c| c != consumer);
    })
}

/// `secrets set-totp <name> on|off` — `want` is the already-parsed
/// `on`/`off` bool; `state` is only its display spelling for the message.
pub fn set_totp(home: &Path, name: &str, want: bool) -> Result<AdminOutcome, String> {
    let state = if want { "on" } else { "off" };
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no policy for secret `{name}`"));
    };
    if policy.require_totp == want {
        return Ok(AdminOutcome::unchanged(format!("secret `{name}` requireTotp already `{state}` — unchanged")));
    }
    policy.require_totp = want;
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;
    Ok(AdminOutcome::changed(format!("secret `{name}` requireTotp set to `{state}`"), format!("policy:{name}")))
}

/// `secrets expose <name> on|off` — same shape as [`set_totp`].
pub fn expose(home: &Path, name: &str, want: bool) -> Result<AdminOutcome, String> {
    let state = if want { "on" } else { "off" };
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no policy for secret `{name}`"));
    };
    if policy.remote == want {
        return Ok(AdminOutcome::unchanged(format!("secret `{name}` remote already `{state}` — unchanged")));
    }
    policy.remote = want;
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;
    Ok(AdminOutcome::changed(format!("secret `{name}` remote set to `{state}`"), format!("policy:{name}")))
}

/// `secrets automate <name> on|off` — flips `Policy::automation.enabled`.
pub fn automate_toggle(home: &Path, name: &str, want: bool) -> Result<AdminOutcome, String> {
    let state = if want { "on" } else { "off" };
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no policy for secret `{name}`"));
    };
    if policy.automation.enabled == want {
        return Ok(AdminOutcome::unchanged(format!("secret `{name}` automation already `{state}` — unchanged")));
    }
    policy.automation.enabled = want;
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;
    Ok(AdminOutcome::changed(format!("secret `{name}` automation set to `{state}`"), format!("policy:{name}")))
}

/// `secrets automate <name> grant|revoke <consumer>` — edits
/// `Policy::automation.consumers`. `want_listed` is `true` for `grant`,
/// `false` for `revoke` — caller already validated `consumer`'s shape
/// (`valid_secret_name`, `commands.rs`'s own job, never duplicated here).
pub fn automate_consumer(home: &Path, name: &str, consumer: &str, want_listed: bool) -> Result<AdminOutcome, String> {
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no policy for secret `{name}`"));
    };
    let already_listed = policy.automation.consumers.iter().any(|c| c == consumer);
    if want_listed == already_listed {
        let verb = if want_listed { "already lists" } else { "does not list" };
        return Ok(AdminOutcome::unchanged(format!("secret `{name}` automation {verb} consumer `{consumer}` — unchanged")));
    }
    if want_listed {
        policy.automation.consumers.push(consumer.to_string());
    } else {
        policy.automation.consumers.retain(|c| c != consumer);
    }
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;
    let verb = if want_listed { "now lists" } else { "no longer lists" };
    Ok(AdminOutcome::changed(format!("secret `{name}` automation {verb} consumer `{consumer}`"), format!("policy:{name}")))
}

/// `secrets migrate <name> [--backend <target>]` — the exact fetch ->
/// (maybe mint) -> store -> flip+save -> remove-old ordering
/// `commands::handle_secrets_migrate` used to run inline (this crate's
/// `AGENTS.md`, "ordering is safety-critical" — unchanged by this phase,
/// still hard-constrained: any failure before the policy save leaves
/// everything untouched, and the old value is only ever removed AFTER the
/// new one is durably stored and the policy flip has already saved).
/// `door` names who's asking, for the caller's own audit line — this
/// function fires none itself (module doc: "argument validation... still
/// lives only in `commands.rs`"; the SAME split applies to auditing —
/// `commands.rs`'s `audit_migrate` on the direct path,
/// `broker::audit_admin` on the socket path, never a third copy here).
pub fn migrate(home: &Path, door: Door, name: &str, target: &str) -> Result<(AdminOutcome, String, String), String> {
    let mut policies = store::load_policies(home).map_err(|e| policy_io_error(home, e))?;
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no policy for secret `{name}`"));
    };
    let source = policy.backend.clone();
    let key = policy.key.clone();
    let _ = door; // reserved for a future per-source-door audit distinction; caller owns auditing today.

    if source == target {
        return Ok((AdminOutcome::unchanged(format!("secret `{name}` already on backend `{target}` — unchanged")), source, target.to_string()));
    }

    let value = crate::backend::fetch_value(home, &source, &key)
        .map_err(|e| format!("secret `{name}`: could not fetch from backend `{source}`: {e}"))?;

    if target == "age" && crate::backend::backend_is_known(home, "age") {
        crate::backend::mint_age_identity_if_needed(home)
            .map_err(|e| format!("secret `{name}`: could not prepare backend `{target}`: {e}"))?;
    }

    crate::backend::store_value(home, target, &key, &value)
        .map_err(|e| format!("secret `{name}`: could not store into backend `{target}`: {e}"))?;

    // Reload+re-find: `store_value`/`mint_age_identity_if_needed` touch no
    // in-memory state here, but re-borrowing `policy` across the two
    // backend calls above would fight the borrow checker for no reason —
    // simplest is finding it once more, immediately before the flip.
    let Some(policy) = policies.iter_mut().find(|p| p.name == name) else {
        return Err(format!("no policy for secret `{name}` (vanished mid-migration)"));
    };
    policy.backend = target.to_string();
    store::save_policies(home, &policies).map_err(|e| policy_io_error(home, e))?;

    let key_lifecycle_note = if target == "age" {
        " — age.key is now the ONLY decryptor of this value; back it up together with values/, \
          since a backup holding the .age files but not age.key restores to nothing"
    } else {
        ""
    };
    let message = match crate::backend::remove_builtin_value(home, &source, &key) {
        Some(Ok(())) => {
            format!("migrated secret `{name}` from `{source}` to `{target}` (old value removed){key_lifecycle_note}")
        }
        Some(Err(e)) => {
            format!("migrated secret `{name}` from `{source}` to `{target}` (old value NOT removed: {e}){key_lifecycle_note}")
        }
        None => format!(
            "migrated secret `{name}` from `{source}` to `{target}` (old value under `{source}` left in place — \
             not a built-in backend, remove it by hand){key_lifecycle_note}"
        ),
    };
    Ok((AdminOutcome::changed(message, format!("policy:{name}")), source, target.to_string()))
}
