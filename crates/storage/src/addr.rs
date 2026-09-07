//! Pure address resolver (messaging/presence plan, P-C1) — the INVERSE of
//! `display::session_label`: that module builds a string for a human to
//! read; this one takes a string a human TYPED and works backward to a
//! session identity. Zero I/O: [`resolve`] takes only slices the caller
//! already has in hand (no stage read, no node-cache read) so it is
//! trivially unit-testable and safe to call from any door (CLI, MCP, A2A).
//!
//! ## Grammar, tried in precedence order
//!
//! `display::session_label` renders `<host>/<role>/<petname> (…<tail4>)`,
//! degrading to `<host>/<role>/<sessionId>` when no petname was minted. This
//! resolver inverts every piece of that grammar a human could plausibly
//! type back in, tried in this fixed order — the FIRST tier that produces
//! any candidate at all wins; later tiers are never consulted once an
//! earlier one has something to say:
//!
//! 1. **exact session id** — `query == candidate.session_id` verbatim (the
//!    degraded-legacy form of the label, or a copy-pasted id). A leading
//!    `session:` prefix — the exact form `graph view --json` emits for a
//!    node id — is stripped before this (or any later) tier runs, so a
//!    copy-pasted node id resolves the same as the bare id it wraps.
//! 2. **id tail4** — `query == short_tail(candidate.session_id)`, the
//!    `…8948` short form the label parenthesizes.
//! 3. **petname** — a bare token (no `/`) equal to a local session's minted
//!    petname.
//! 4. **host/role/petname compound** — exactly three `/`-separated parts;
//!    the first must equal the caller's own `host`, the second and third
//!    match a candidate's `role`/`petname` pair. This is `session_label`'s
//!    full line, typed back verbatim.
//! 5. **`node/<rest>`** — a leading component (up to the first `/`) that
//!    names a KNOWN node defers resolution instead of resolving locally:
//!    [`Resolution::Remote`] carries the node name and the remainder
//!    verbatim, unresolved — the node's own graph resolves `query` on its
//!    side (C3 sends it over as the query half of a remote lookup, not
//!    something this crate ever inspects further).
//!
//! ## Ambiguity is an error, never first-match-wins
//!
//! Within a single tier, more than one candidate matching is
//! [`Resolution::Ambiguous`] — carrying every candidate's session id, never
//! a silent pick of whichever happened to be first in the slice. Two
//! classes are exercised in the tests below: an id-tail4 collision (two
//! sessions whose ids happen to share a last-4 tail) and a petname
//! collision (two still-live local sessions holding the same petname — not
//! possible through `petname::mint_for`'s own discipline, but this resolver
//! doesn't get to assume its caller's data is clean, so a hand-edited or
//! corrupted stage file still gets a safe answer instead of a wrong guess).
//!
//! Ambiguity is strictly WITHIN a tier. ACROSS tiers there is no ambiguity
//! by construction: tiers are consulted in order and the first one with any
//! candidate wins outright, full stop — so a query that could structurally
//! read as BOTH a tier-4 `host/role/petname` line and a tier-5 `node/<rest>`
//! (e.g. this box's own hostname is also the name of a registered node, and
//! the query has exactly two slashes) resolves via tier 4 alone whenever
//! tier 4 finds a candidate; tier 5 is only ever reached when every earlier
//! tier came up completely empty.
//!
//! ## The bare-known-node-name decision
//!
//! A bare token (no `/`) that names a known node but matches no local
//! session is `NotFound`, never [`Resolution::Remote`]. The `node/<rest>`
//! grammar (tier 5) requires the slash form by construction — there is no
//! `<rest>` to defer without one, and C3 (the first real consumer) always
//! resolves a query to a specific remote SESSION, never "the whole node" —
//! so a `Remote` with an empty, unrequested query is a feature nothing
//! downstream reads. `node/` (a literal trailing slash, empty `<rest>`) is
//! the deliberately different case: the slash form WAS typed, so tier 5
//! still applies and yields `Remote { node, query: "" }` — an explicit
//! "resolve nothing further on your side" query the node is free to reject,
//! rather than this crate inventing a whole-node reference type nobody
//! asked for.
//!
//! A bare token that happens to equal BOTH a local petname AND a known node
//! name is likewise not ambiguous: tier 3 (petname) is strictly ahead of
//! tier 5 in precedence, and tier 5 never engages on a slash-free query in
//! the first place, so the petname wins deterministically every time.
//!
//! ## Case handling
//!
//! Every comparison is case-sensitive, exactly as typed. `session_label`
//! never folds case on any of its pieces (hostnames come from `gethostname`
//! or an env override verbatim, petnames are minted lowercase-only, roles
//! are the literal `"root"`/`"child"` tokens) — inverting a display that
//! never changes case by silently folding case back here would accept
//! typos the label itself could never have produced.
//!
//! ## Consumers (planned, not present)
//!
//! Nothing registers or calls this module yet — it is a library addition
//! only, per this phase's scope. The messaging/presence plan's later phases
//! are the intended callers: **C2** (`aoide session`/`--hosts`, formerly
//! `aoide who`) uses it to resolve a
//! filter argument against the live-probed roster; **C3** (`graph send
//! --to <target>`) uses it to turn `--to` into either a local `sessionId`
//! (existing send path, unchanged) or a `Remote { node, query }` it hands
//! to the node as an A2A `message/send` lookup.

use crate::display::short_tail;

/// One local session as the resolver sees it: the three fields
/// `display::session_label` reads back out of. `role` is DAG-derived
/// (`"root"`/`"child"` today) — this crate has no DAG, so the caller
/// (`conduct`, which already computes the same value for `session_label`
/// itself) supplies it precomputed rather than this module reaching for one.
#[derive(Debug, Clone, Copy)]
pub struct LocalCandidate<'a> {
    pub session_id: &'a str,
    pub petname: Option<&'a str>,
    pub role: &'a str,
}

impl<'a> LocalCandidate<'a> {
    /// Build a candidate from a live `SessionRecord` plus its caller-derived
    /// `role` — the ergonomic constructor C2/C3 are expected to map their
    /// session slice through (mirrors `display::session_label`'s own
    /// `(rec, host, role)` argument shape). A caller that wants a "done"
    /// session excluded from resolution filters it out of the slice before
    /// calling [`resolve`] — same discipline `petname::mint_for` uses for
    /// liveness, not re-implemented here since this module has no `state`
    /// opinion of its own.
    pub fn from_record(rec: &'a crate::records::SessionRecord, role: &'a str) -> Self {
        Self {
            session_id: rec.session_id.as_str(),
            petname: rec.petname.as_deref(),
            role,
        }
    }
}

/// The outcome of resolving a typed query against a known candidate set.
/// Ambiguity is a first-class value, never a silently-picked first match —
/// see the module doc's "Ambiguity is an error" section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Resolved to exactly one local session id.
    Local(String),
    /// A leading `node/` component named a known node; `query` is the
    /// unresolved remainder, verbatim, for the node's own side to resolve.
    Remote { node: String, query: String },
    /// More than one candidate matched within the SAME tier — every
    /// matching session id, in candidate-slice order.
    Ambiguous(Vec<String>),
    /// No tier produced any candidate.
    NotFound,
}

/// Resolve `query` against `locals` (this box's known sessions) and `nodes`
/// (this box's known node names) as of the caller's own snapshot — zero I/O,
/// see the module doc for the full grammar and precedence. `host` is this
/// box's own display host name (`display::local_host_name()`, resolved once
/// by the caller — mirrors every other display-grammar call site's "host
/// resolved once per pass" rule rather than this function reaching for it
/// itself).
pub fn resolve(query: &str, host: &str, locals: &[LocalCandidate<'_>], nodes: &[&str]) -> Resolution {
    let query = query.trim();
    if query.is_empty() {
        return Resolution::NotFound;
    }
    // A known `session:` prefix (the exact form `graph view --json` emits
    // for a node id) is stripped before any tier runs, so a copy-pasted
    // node id resolves identically to the bare id it wraps. No other
    // prefix is special-cased — an unrecognised one is left verbatim and
    // simply fails every tier below, same as today.
    let query = query.strip_prefix("session:").unwrap_or(query);

    // Tier 1: exact session id.
    if let Some(r) = match_tier(locals, |c| c.session_id == query) {
        return r;
    }

    // Tier 2: id tail4 — the `…8948` short form the label parenthesizes.
    if let Some(r) = match_tier(locals, |c| short_tail(c.session_id) == query) {
        return r;
    }

    // Tier 3: bare petname — only when the query carries no `/` at all, so
    // it can never shadow the compound or node forms below.
    if !query.contains('/') {
        if let Some(r) = match_tier(locals, |c| c.petname == Some(query)) {
            return r;
        }
    }

    // Tier 4: `host/role/petname`, exactly three parts, first part = this
    // box's own host.
    let parts: Vec<&str> = query.split('/').collect();
    if parts.len() == 3 && parts[0] == host {
        let (q_role, q_petname) = (parts[1], parts[2]);
        if let Some(r) = match_tier(locals, |c| c.role == q_role && c.petname == Some(q_petname)) {
            return r;
        }
    }

    // Tier 5: `node/<rest>` — a leading component naming a KNOWN node
    // defers resolution; the rest is not this crate's to interpret further.
    if let Some((node, rest)) = query.split_once('/') {
        if nodes.contains(&node) {
            return Resolution::Remote {
                node: node.to_string(),
                query: rest.to_string(),
            };
        }
    }

    Resolution::NotFound
}

/// Compose [`resolve`] with the P-D5 hub preference: when every tier above
/// comes up completely empty (`Resolution::NotFound` — no exact id, no
/// tail4, no petname, no host/role match, no node-name match), a
/// hub-designated node (if the caller names one via `hub`) is offered as
/// one last, least-specific candidate — `Resolution::Remote { node: hub,
/// query }`, carrying the ORIGINAL trimmed query verbatim, since no
/// `node/<rest>` prefix was ever recognized in it for there to be anything
/// to strip. Any OTHER resolution — `Local`, tier 5's own `Remote`, or
/// `Ambiguous` — passes through completely untouched: the hub is a
/// fallback of last resort, never a shadow over any tier's existing
/// precedence (`docs/architecture/AOIDED.md`'s "The hub option": "resolution
/// prefers the hub only when nothing else matches"). `hub: None` (no node
/// currently marked hub, `node_store::Node::hub`) makes this an identity
/// wrapper over [`resolve`] — a mesh with no hub behaves exactly as before
/// this function existed.
pub fn resolve_with_hub(
    query: &str,
    host: &str,
    locals: &[LocalCandidate<'_>],
    nodes: &[&str],
    hub: Option<&str>,
) -> Resolution {
    match resolve(query, host, locals, nodes) {
        Resolution::NotFound => match hub {
            Some(name) => Resolution::Remote {
                node: name.to_string(),
                query: query.trim().to_string(),
            },
            None => Resolution::NotFound,
        },
        other => other,
    }
}

/// Apply one tier's predicate over `locals`, returning `None` when nothing
/// matched (so the caller falls through to the next tier), `Some(Local)` on
/// exactly one hit, `Some(Ambiguous)` on more than one — the one piece of
/// match-then-classify logic every tier above shares.
fn match_tier(locals: &[LocalCandidate<'_>], pred: impl Fn(&LocalCandidate<'_>) -> bool) -> Option<Resolution> {
    let hits: Vec<&str> = locals.iter().filter(|c| pred(c)).map(|c| c.session_id).collect();
    match hits.len() {
        0 => None,
        1 => Some(Resolution::Local(hits[0].to_string())),
        _ => Some(Resolution::Ambiguous(hits.into_iter().map(String::from).collect())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Case {
        name: &'static str,
        query: &'static str,
        host: &'static str,
        locals: Vec<LocalCandidate<'static>>,
        nodes: Vec<&'static str>,
        expected: Resolution,
    }

    fn cand(session_id: &'static str, petname: Option<&'static str>, role: &'static str) -> LocalCandidate<'static> {
        LocalCandidate { session_id, petname, role }
    }

    fn cases() -> Vec<Case> {
        vec![
            // ── Tier 1: exact session id ─────────────────────────────────
            Case {
                name: "exact id hits a unique session",
                query: "sess-aaaa-1111",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "exact id beats every later tier when it matches",
                // Deliberately shaped so tail4 ("root") would ALSO hit a
                // different candidate if tier 1 didn't win outright first.
                query: "sess-aaaa-root",
                host: "sakaki",
                locals: vec![
                    cand("sess-aaaa-root", Some("brave-otter"), "root"),
                    cand("sess-bbbb-root", Some("calm-thorn"), "child"),
                ],
                nodes: vec![],
                expected: Resolution::Local("sess-aaaa-root".into()),
            },
            Case {
                // The exact form `graph view --json` emits for a node id
                // (`session:<id>`) round-trips through `--to`/`session
                // --hosts` just like a bare copy-pasted id.
                name: "a session:-prefixed id resolves the same as the bare id",
                query: "session:sess-aaaa-1111",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                // Only the KNOWN `session:` prefix is special-cased — an
                // unrecognised one is left verbatim and still fails every
                // tier, exactly as before this fix.
                name: "an id with an unknown prefix is still not found",
                query: "nodeish:sess-aaaa-1111",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::NotFound,
            },
            // ── Tier 2: id tail4 ──────────────────────────────────────────
            Case {
                name: "tail4 hits a unique session",
                query: "1111",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "tail4 collision is ambiguous with every hit",
                query: "1111",
                host: "sakaki",
                locals: vec![
                    cand("sess-aaaa-1111", Some("brave-otter"), "root"),
                    cand("sess-cccc-1111", None, "root"),
                ],
                nodes: vec![],
                expected: Resolution::Ambiguous(vec!["sess-aaaa-1111".into(), "sess-cccc-1111".into()]),
            },
            // ── Tier 3: petname ───────────────────────────────────────────
            Case {
                name: "petname hits a unique session",
                query: "brave-otter",
                host: "sakaki",
                locals: vec![
                    cand("sess-aaaa-1111", Some("brave-otter"), "root"),
                    cand("sess-bbbb-2222", Some("calm-thorn"), "child"),
                ],
                nodes: vec![],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "petname collision (corrupted/hand-edited data) is ambiguous",
                query: "brave-otter",
                host: "sakaki",
                locals: vec![
                    cand("sess-aaaa-1111", Some("brave-otter"), "root"),
                    cand("sess-dddd-3333", Some("brave-otter"), "child"),
                ],
                nodes: vec![],
                expected: Resolution::Ambiguous(vec!["sess-aaaa-1111".into(), "sess-dddd-3333".into()]),
            },
            Case {
                name: "legacy petname-less session is never matched by petname tier",
                query: "sess-cccc-1111",
                host: "sakaki",
                locals: vec![cand("sess-cccc-1111", None, "root")],
                nodes: vec![],
                expected: Resolution::Local("sess-cccc-1111".into()),
            },
            // ── Tier 4: host/role/petname compound ───────────────────────
            Case {
                name: "host/role/petname hits a unique session",
                query: "sakaki/root/brave-otter",
                host: "sakaki",
                locals: vec![
                    cand("sess-aaaa-1111", Some("brave-otter"), "root"),
                    cand("sess-dddd-3333", Some("brave-otter"), "child"),
                ],
                nodes: vec![],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "host/role/petname ambiguous when role+petname collide",
                query: "sakaki/root/brave-otter",
                host: "sakaki",
                locals: vec![
                    cand("sess-aaaa-1111", Some("brave-otter"), "root"),
                    cand("sess-eeee-4444", Some("brave-otter"), "root"),
                ],
                nodes: vec![],
                expected: Resolution::Ambiguous(vec!["sess-aaaa-1111".into(), "sess-eeee-4444".into()]),
            },
            Case {
                name: "host/role/petname with the wrong host is not found (no node named for it)",
                query: "yomi-strix/root/brave-otter",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::NotFound,
            },
            Case {
                name: "host/role/petname with the wrong role is not found",
                query: "sakaki/child/brave-otter",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::NotFound,
            },
            // ── Tier 5: node/<rest> ───────────────────────────────────────
            Case {
                name: "node/<rest> defers to Remote for a known node",
                query: "yomi-strix/brave-otter",
                host: "sakaki",
                locals: vec![],
                nodes: vec!["yomi-strix"],
                expected: Resolution::Remote { node: "yomi-strix".into(), query: "brave-otter".into() },
            },
            Case {
                name: "node/<rest> with a multi-segment rest passes it through verbatim",
                query: "yomi-strix/root/brave-otter",
                host: "sakaki",
                locals: vec![],
                nodes: vec!["yomi-strix"],
                expected: Resolution::Remote { node: "yomi-strix".into(), query: "root/brave-otter".into() },
            },
            Case {
                name: "slash form with an unknown node is not found",
                query: "ghost-node/brave-otter",
                host: "sakaki",
                locals: vec![],
                nodes: vec!["yomi-strix"],
                expected: Resolution::NotFound,
            },
            Case {
                name: "a trailing-slash node form with empty rest still resolves via tier 5",
                query: "yomi-strix/",
                host: "sakaki",
                locals: vec![],
                nodes: vec!["yomi-strix"],
                expected: Resolution::Remote { node: "yomi-strix".into(), query: "".into() },
            },
            // ── Cross-tier precedence (not ambiguity — see module doc) ───
            Case {
                name: "host/role/petname tier wins outright over a same-named node when it has a hit",
                query: "sakaki/root/brave-otter",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                // "sakaki" is ALSO a registered node name — tier 4 still wins,
                // tier 5 is never even consulted.
                nodes: vec!["sakaki"],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "host/role/petname tier empty falls through to node/<rest> for the same query shape",
                query: "sakaki/root/ghost-name",
                host: "sakaki",
                // No local session named `ghost-name` as `root` — tier 4
                // finds nothing, so tier 5 gets a turn.
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec!["sakaki"],
                expected: Resolution::Remote { node: "sakaki".into(), query: "root/ghost-name".into() },
            },
            Case {
                name: "a bare token matching both a local petname and a node name resolves to the petname, deterministically",
                query: "brave-otter",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                // A node coincidentally sharing the petname's exact text —
                // tier 5 never engages on a slash-free query, so this is not
                // ambiguous, it's tier 3 winning outright.
                nodes: vec!["brave-otter"],
                expected: Resolution::Local("sess-aaaa-1111".into()),
            },
            Case {
                name: "a bare known-node-name with no local match is NotFound, not a whole-node Remote",
                query: "yomi-strix",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec!["yomi-strix"],
                expected: Resolution::NotFound,
            },
            // ── Case handling ─────────────────────────────────────────────
            Case {
                name: "petname match is case-sensitive, exactly as the label renders it",
                query: "Brave-Otter",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::NotFound,
            },
            Case {
                name: "tail4 match is case-sensitive, exactly as the label renders it",
                query: "AB12",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-ab12", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::NotFound,
            },
            // ── Empty / garbage input ─────────────────────────────────────
            Case {
                name: "an empty query is not found",
                query: "",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec!["yomi-strix"],
                expected: Resolution::NotFound,
            },
            Case {
                name: "a whitespace-only query is not found",
                query: "   ",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec![],
                expected: Resolution::NotFound,
            },
            Case {
                name: "garbage punctuation matches nothing in any tier",
                query: "???/???",
                host: "sakaki",
                locals: vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")],
                nodes: vec!["yomi-strix"],
                expected: Resolution::NotFound,
            },
            Case {
                name: "an empty candidate/node set is always not found",
                query: "brave-otter",
                host: "sakaki",
                locals: vec![],
                nodes: vec![],
                expected: Resolution::NotFound,
            },
        ]
    }

    #[test]
    fn resolve_matches_the_grammar_table() {
        for c in cases() {
            let got = resolve(c.query, c.host, &c.locals, &c.nodes);
            assert_eq!(got, c.expected, "case failed: {}", c.name);
        }
    }

    // ── `resolve_with_hub` — the P-D5 hub-preference wrapper ─────────────────

    #[test]
    fn hub_is_used_only_when_every_tier_finds_nothing() {
        let locals = vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")];

        // No hub configured: identical to plain `resolve` — NotFound stays
        // NotFound, not silently upgraded.
        assert_eq!(
            resolve_with_hub("ghost-name", "sakaki", &locals, &[], None),
            Resolution::NotFound
        );

        // A hub IS configured, and nothing else matches: the hub wins as
        // the last-resort remote, carrying the original query verbatim.
        assert_eq!(
            resolve_with_hub("ghost-name", "sakaki", &locals, &[], Some("hub-box")),
            Resolution::Remote { node: "hub-box".into(), query: "ghost-name".into() }
        );
    }

    #[test]
    fn an_exact_local_match_beats_the_hub_outright() {
        let locals = vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")];
        // The query resolves locally via tier 1 — the hub is never even
        // consulted, even though one is configured.
        assert_eq!(
            resolve_with_hub("sess-aaaa-1111", "sakaki", &locals, &[], Some("hub-box")),
            Resolution::Local("sess-aaaa-1111".into())
        );
    }

    #[test]
    fn tier_5_node_rest_beats_the_hub_outright() {
        let locals: Vec<LocalCandidate<'_>> = vec![];
        // `yomi-strix` is a KNOWN node distinct from the hub — tier 5 wins,
        // the hub (a different node) never gets a turn.
        assert_eq!(
            resolve_with_hub("yomi-strix/brave-otter", "sakaki", &locals, &["yomi-strix"], Some("hub-box")),
            Resolution::Remote { node: "yomi-strix".into(), query: "brave-otter".into() }
        );
    }

    #[test]
    fn ambiguous_never_falls_through_to_the_hub() {
        let locals = vec![
            cand("sess-aaaa-1111", Some("brave-otter"), "root"),
            cand("sess-dddd-3333", Some("brave-otter"), "child"),
        ];
        // A genuine collision is NOT "nothing matches" — it must surface as
        // Ambiguous, never get silently resolved via the hub.
        assert_eq!(
            resolve_with_hub("brave-otter", "sakaki", &locals, &[], Some("hub-box")),
            Resolution::Ambiguous(vec!["sess-aaaa-1111".into(), "sess-dddd-3333".into()])
        );
    }

    #[test]
    fn no_hub_and_no_match_is_notfound_unchanged() {
        let locals = vec![cand("sess-aaaa-1111", Some("brave-otter"), "root")];
        assert_eq!(
            resolve_with_hub("nobody-here", "sakaki", &locals, &["yomi-strix"], None),
            Resolution::NotFound
        );
    }

    #[test]
    fn from_record_carries_session_id_and_petname_through_unmodified() {
        let rec = crate::records::SessionRecord {
            session_id: "sess-zzzz-9999".into(),
            petname: Some("misty-comet".into()),
            ..Default::default()
        };
        let c = LocalCandidate::from_record(&rec, "root");
        assert_eq!(c.session_id, "sess-zzzz-9999");
        assert_eq!(c.petname, Some("misty-comet"));
        assert_eq!(c.role, "root");
    }

    #[test]
    fn from_record_carries_a_legacy_petname_less_session_as_none() {
        let rec = crate::records::SessionRecord {
            session_id: "sess-legacy".into(),
            petname: None,
            ..Default::default()
        };
        let c = LocalCandidate::from_record(&rec, "child");
        assert_eq!(c.petname, None);
    }
}
