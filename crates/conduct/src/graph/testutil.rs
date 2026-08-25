//! Shared `#[cfg(test)]` fixtures reused across the `graph` submodule test
//! suites: session/project builders, `Invocation` constructors per verb
//! family, a unique per-test stage dir, and the env-var save/restore guard.
//! `pub(crate)` (not `pub(in crate::graph)`): the whole module is
//! `#[cfg(test)]`-gated at its `mod testutil;` declaration in `graph.rs`, so
//! nothing here ships in a non-test build regardless of the wider visibility.

use super::model::{Project, SessionRecord};
use super::window::TermWindow;
use aoide_protocol::Invocation;
use serde_json::Map;
use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) fn term_win(addr: &str, class: &str, cwd: &str) -> TermWindow {
    TermWindow {
        address: addr.into(),
        class: class.into(),
        title: String::new(),
        workspace: Some(1),
        pid: Some(4321),
        mapped: true,
        cwd: cwd.into(),
    }
}
pub(crate) fn session(
    id: &str,
    cwd: &str,
    state: &str,
    started: &str,
    parent: Option<&str>,
) -> SessionRecord {
    SessionRecord {
        session_id: id.into(),
        agent: "claude".into(),
        window_address: format!("0x{id}"),
        cwd: cwd.into(),
        state: state.into(),
        started_at: started.into(),
        parent_session_id: parent.map(str::to_string),
        conductable: None,
        socket: None,
        title: None,
        pid: None,
        workspace: None,
        activity: None,
        kind: None,
        say: None,
        tool: None,
        model: None,
        context_tokens: None,
        context_ceiling: None,
        needs_sudo: None,
        log_path: None,
        petname: None,
        hook_ancestry: Vec::new(),
        headless: false,
        harness_session_id: None,
        extra: Map::new(),
    }
}
pub(crate) fn fixture_projects() -> Vec<Project> {
    vec![
        Project {
            name: "nested".into(),
            path: "/home/k/Aoide/sub".into(),
        },
        Project {
            name: "aoide".into(),
            path: "/home/k/Aoide".into(),
        },
    ]
}
pub(crate) fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}
/// Monotonic per-process counter backing `unique_stage`'s directory name —
/// see that function's doc for why a counter, not a nanosecond timestamp.
static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Returns a fresh, already-created temp directory for one test's stage
/// (frequently doubled as `$XDG_RUNTIME_DIR`, one path segment above where a
/// `session-<id>.sock` control socket gets bound). The directory name is
/// deliberately SHORT: a hash of `tag` plus pid plus a monotonic counter —
/// never the tag text itself, never a full nanosecond timestamp. `AF_UNIX`
/// addresses cap at `sizeof(sun_path)` (108 bytes on Linux), and this path
/// sits under `$TMPDIR`, which varies (`/tmp` bare vs. `/tmp/nix-shell.XXXXXX`
/// under `nix develop`). The old `aoide-graph-<tag>-<pid>-<nanos>` name ate
/// most of that budget on its own — a long tag plus a 19-digit nanosecond
/// timestamp plus a nix `$TMPDIR` plus `/aoide/session-<id>.sock` blew past
/// `SUN_LEN` and panicked, poisoning `env_lock` for every test after it
/// (#75). The hash keeps some of the tag's grep-ability (same tag, same
/// prefix) without its length; the counter — not the timestamp — is what
/// actually guarantees uniqueness between calls in the same process.
pub(crate) fn unique_stage(tag: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    tag.hash(&mut hasher);
    let tag_hash = (hasher.finish() as u32) & 0xffff;
    let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut dir = std::env::temp_dir();
    dir.push(format!("ao{:x}-{:x}-{:x}", std::process::id(), tag_hash, seq));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
pub(crate) fn invocation(path: &[&str], args: &[&str]) -> Invocation {
    Invocation {
        path: path.iter().map(|s| s.to_string()).collect(),
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: BTreeMap::new(),
        door: aoide_protocol::Door::Cli,
    }
}
pub(crate) fn wrap_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
    Invocation {
        path: vec!["graph".into(), "wrap".into()],
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: flags
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        door: aoide_protocol::Door::Cli,
    }
}
pub(crate) fn conduct_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
    Invocation {
        path: vec!["conduct".into()],
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: flags
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        door: aoide_protocol::Door::Cli,
    }
}
pub(crate) fn spawn_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
    Invocation {
        path: vec!["graph".into(), "spawn".into()],
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: flags
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        door: aoide_protocol::Door::Cli,
    }
}
pub(crate) fn send_invocation(args: &[&str], flags: &[(&str, &str)]) -> Invocation {
    Invocation {
        path: vec!["graph".into(), "send".into()],
        args: args.iter().map(|s| s.to_string()).collect(),
        flags: flags
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        door: aoide_protocol::Door::Cli,
    }
}
pub(crate) struct EnvVars {
    keys: Vec<(&'static str, Option<String>)>,
}
impl EnvVars {
    pub(crate) fn save(keys: &[&'static str]) -> Self {
        EnvVars {
            keys: keys.iter().map(|k| (*k, std::env::var(k).ok())).collect(),
        }
    }
}
impl Drop for EnvVars {
    fn drop(&mut self) {
        for (k, v) in &self.keys {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
pub(crate) fn flag_invocation(path: &[&str], flags: &[(&str, &str)]) -> Invocation {
    Invocation {
        path: path.iter().map(|s| s.to_string()).collect(),
        args: vec![],
        flags: flags
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        door: aoide_protocol::Door::Cli,
    }
}
