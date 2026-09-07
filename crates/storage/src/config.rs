//! The portable runtime config — `$AOIDE_ROOT/config.toml` (task #135 P-C,
//! CONTRACTS.md §4's own `config.toml` subsection).
//!
//! **INTENT lives here; STATE stays in `state/*.json`.** Every other file
//! this crate owns records what HAPPENED (`nodes.json`'s records/allows/hub,
//! the pairing park queues, `advertise.json`'s switch); this one records what
//! an operator WANTS, ahead of anything happening. The two never mix, and no
//! value ever migrates between them.
//!
//! **Portable, because core is portable.** `aoide` is cargo-buildable on any
//! Linux with no nix shell-outs and no NixOS assumption (root `AGENTS.md`), so
//! a config decision for a CORE command cannot live in a NixOS module option:
//! on a non-nix host that option does not exist, and "rebuild to change a
//! grant" is not an operation. Nix is ONE authoring front-end that WRITES this
//! file, never its owner — `modules/nucleus/config.nix` renders the whole file
//! to a read-only store path and points [`ENV_CONFIG`] at it. Immutability IS
//! the provenance: there is no marker field to go stale, and the two worlds
//! never write the same path, so a rebuild structurally cannot eat a CLI edit.
//!
//! **TOML, not JSON or YAML.** This is the one file a human edits, and the
//! reasoning behind a grant belongs beside it — JSON has nowhere to put that.
//! YAML's implicit coercion and whitespace sensitivity are the wrong posture
//! for a file carrying grants: this one must fail loudly, never guess. The
//! same reasoning drives [`Config`]'s `deny_unknown_fields` — a typo'd key in
//! a grants file is refused by name, never silently ignored.
//!
//! **[`SCHEMA`] is a walkable table of the SETTABLE surface, not knowledge
//! scattered through match arms.** Sections, their keys, each key's value
//! vocabulary, and how to read that key off a typed [`Config`] all live in
//! one const table; [`validate`], [`set`], and `aoide config`'s own listing
//! every walk it rather than restating it. A new key is one table row plus
//! its struct field. Two sections today, neither aware the other exists:
//! `[pairing]`'s `defaultGrant` is a [`ValueKind::ClosedList`] (closed
//! vocabulary, `node_store::NODE_CAPABILITIES`); `[upkeep]`'s `verifyCommand`
//! is a [`ValueKind::Scalar`] — the check lane's own verification command
//! (`aoide session hook`'s SessionStart/Stop wiring), free-form because core
//! cannot know what "clean" means on every host. A scalar key is the one
//! place [`SCHEMA`] gives up checking a vocabulary: there isn't one to check.
//! **[`Mesh`] is validated but deliberately NOT in [`SCHEMA`] (task #135
//! P4).** A mesh's keys are an operator's own node names, chosen at write
//! time — [`SectionSpec`]/[`KeySpec`] are entirely `&'static`, and admitting
//! them would mean rebuilding the whole table as an owned, dynamically-built
//! one to serve one section. `[mesh]` is validated directly in [`validate`]
//! instead, so a typo or an out-of-vocabulary grant still fails loudly; it is
//! simply never reachable from `aoide config set`, which walks [`SCHEMA`]
//! alone. `aoide mesh` (`aoide-client`) is the read and `aoide mesh pair` is
//! the converge that acts on it — and neither writes this file, nor is ever
//! a `config set` target.
//!
//! **Resolution ([`source`]), identical at every entry point** — the `aoide`
//! CLI, the `aoided` daemon, and the stdio MCP façade all reach this one
//! function, so there is no per-door variant to drift:
//!
//! 1. [`ENV_CONFIG`] set to an absolute path → that file, MANAGED (read-only;
//!    [`set`] refuses it and names it).
//! 2. else `$AOIDE_ROOT/config.toml` → UNMANAGED, writable by [`set`].
//!
//! A missing file is all defaults, never an error — the same tolerate-missing
//! stance `advertise::enabled` and `node_store::load_nodes` already hold. A
//! file that EXISTS but doesn't parse, or carries an unknown key or an unknown
//! capability, is a loud error naming the offence.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The config file's own name under [`crate::fs::root`].
pub const CONFIG_FILE: &str = "config.toml";

/// The env var a nix-rendered (or otherwise externally managed) config is
/// pointed at. Absolute-path-wins, the same discipline `$AOIDE_ROOT`/
/// `$AOIDE_STAGE_DIR`/`$AOIDE_STATE_DIR` already hold — a runtime path is
/// never resolved against an arbitrary cwd.
pub const ENV_CONFIG: &str = "AOIDE_CONFIG";

/// The config file's own schema version — bumped only on an incompatible
/// shape change, same stance as every other `schemaVersion` this crate
/// writes. Deliberately not a field IN the file: a config a human hand-writes
/// should not have to carry bookkeeping, and `deny_unknown_fields` would
/// refuse it if they typed one.
pub const SCHEMA_VERSION: &str = "0";

// ── Schema v0, as a typed struct AND as a walkable table ────────────────────

/// The whole config, v0: one section. A new section lands with the consumer
/// that reads it, never ahead of one — an option nothing consults is a
/// promise the code doesn't keep.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub pairing: Pairing,
    #[serde(default)]
    pub upkeep: Upkeep,
    /// `[mesh.<name>]` — zero or more declared meshes (task #135 P4), keyed
    /// by the operator's own mesh name. VALIDATED (see [`validate`]) but
    /// deliberately not in [`SCHEMA`] — see the module doc's own note on
    /// why. Empty by default: a config predating this field, or one that
    /// simply declares no mesh, loads byte-identically to before it existed.
    #[serde(default)]
    pub mesh: BTreeMap<String, Mesh>,
}

/// `[pairing]` — the pairing ceremony's own intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pairing {
    /// The capability set a node is granted when it FIRST becomes verified.
    /// Values come from `node_store::NODE_CAPABILITIES`, the same closed
    /// vocabulary `node allow` already validates against — never a second,
    /// drifting list. Default `["read"]`: read is what a node needs to be
    /// useful, spawn is what it needs to run code here, and the second is an
    /// explicit widening.
    #[serde(rename = "defaultGrant", default = "default_grant")]
    pub default_grant: Vec<String>,
}

fn default_grant() -> Vec<String> {
    vec!["read".to_string()]
}

impl Default for Pairing {
    fn default() -> Self {
        Pairing { default_grant: default_grant() }
    }
}

/// `[upkeep]` — the check lane's own intent (`aoide session hook`'s
/// SessionStart/Stop wiring, `aoide-upkeep::checklane`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upkeep {
    /// The shell command the check lane runs to answer "is the working tree
    /// clean" — on a nix host, a `nix flake check` invocation naming the fast
    /// checks only (fmt/nix-lint/discovery/song-shape/no-song-read/
    /// surface-ownership: the vm-boot/pkg-*/portability checks are too slow
    /// for a hook and stay manual); on a non-nix host, `cargo test`/`make
    /// check`/whatever the project uses. Empty (the default) disables the
    /// lane outright — core ships with zero opinion on what "clean" means.
    #[serde(rename = "verifyCommand", default)]
    pub verify_command: String,
}

impl Default for Upkeep {
    fn default() -> Self {
        Upkeep { verify_command: String::new() }
    }
}

/// `[mesh.<name>]` — a declared mesh: a named set of nodes an operator
/// intends to keep paired, meant to be deployed identically to every box in
/// it (task #135 P4). This is INTENT, same as the rest of [`Config`] — it
/// names nothing about whether a node is actually paired yet; `aoide mesh`
/// (`aoide-client`) compares it against `state/nodes.json` and reports the
/// difference. Validated in [`validate`] (mesh/node names, hop shape, grant
/// vocabulary, no name shared across two meshes) but never in [`SCHEMA`] —
/// see the module doc.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mesh {
    /// A capability set, declared against the same closed vocabulary
    /// `pairing.defaultGrant` uses (`node_store::NODE_CAPABILITIES`), never
    /// a second list. `aoide mesh pair` stamps it at a FIRST verification —
    /// it rides the ceremony as `PairFinish::grant` exactly as a typed
    /// `aoide pair --allow` would, so `node_store::upsert_paired_node`
    /// leaves an already-verified node's `allows` untouched and a re-pair
    /// never re-grants. Absent means "this mesh declares no override": the
    /// commit then falls through to `resolve_grant` (`aoide-client`), which
    /// reads `pairing.defaultGrant`. An EMPTY list is the distinct, real
    /// "grant nothing" intent, never the same thing as absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Vec<String>>,
    /// A declared claim that every node in this mesh is operated by the
    /// SAME human. Validated and stored; shown back by `aoide config` and
    /// `aoide mesh`, and read by `mesh pair` for the one line saying the
    /// claim was declared and not acted on. What, if anything, may ever act
    /// on it is not yet decided — it touches the mutual-code pairing
    /// invariant (`docs/architecture/PAIRING.md`'s "Mesh declaration"
    /// section) and is deferred. Default `false`.
    #[serde(rename = "sameOperator", default)]
    pub same_operator: bool,
    /// `name -> ssh hop` (`tunnel::parse_via`'s own `ssh://[user@]host
    /// [:port]` shape). A map, not an array of `{name, via}` records — the
    /// map's own keys make a duplicate node name within one mesh
    /// structural, not a second check to write.
    ///
    /// One of these keys is expected to name THIS box: `drift`
    /// (`aoide-client`) matches it against `display::local_host_name()` by
    /// bare string equality, nothing fuzzier. The key must be exactly what
    /// that function returns, or this box's own entry is indistinguishable
    /// from a genuinely unpaired node. `valid_node_name` accepts only
    /// lowercase letters, digits, and `-`, so a `local_host_name()` that
    /// comes back as an FQDN or mixed-case OS hostname can never be
    /// declared here at all — the same known gap `pair`'s own self-detection
    /// already carries for a custom `--node-name` (`PAIRING.md:599-612`).
    #[serde(default)]
    pub nodes: BTreeMap<String, String>,
}

/// What shape a key's value takes, and what it may contain. A scalar key has
/// no vocabulary to check — any string is valid, because [`Upkeep`]'s verify
/// command is the one config value core cannot itself pass judgment on.
/// Nothing outside [`parse_value`]/[`render_value`]/[`validate`] branches on
/// a key's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// A list whose every element must appear in this vocabulary. Typed at a
    /// command line as a comma-separated list; empty means the empty list.
    ClosedList(&'static [&'static str]),
    /// A free-form string — read back as [`KeySpec::read`]'s one-element
    /// `Vec`, so the walkable-table shape never forks for scalars, but never
    /// comma-split and never vocabulary-checked.
    Scalar,
}

/// One key in one section.
pub struct KeySpec {
    /// The key as it reads in the file and after the dot at `config set`.
    pub name: &'static str,
    pub kind: ValueKind,
    pub summary: &'static str,
    /// This key's current value, read off a typed [`Config`] — the seam that
    /// lets a table walker (validator, printer, and the value menu a later
    /// interactive picker draws) reach a key without knowing which struct
    /// field holds it. Every value is a string list, matching [`ValueKind`]'s
    /// one variant.
    pub read: fn(&Config) -> Vec<String>,
}

/// One section.
pub struct SectionSpec {
    /// The section as it reads in the file and before the dot at `config set`.
    pub name: &'static str,
    pub summary: &'static str,
    pub keys: &'static [KeySpec],
}

/// The whole config surface, walkable. Everything that needs to know what a
/// config key IS reads this — never a match on string literals.
pub const SCHEMA: &[SectionSpec] = &[
    SectionSpec {
        name: "pairing",
        summary: "The pairing ceremony's own intent.",
        keys: &[KeySpec {
            name: "defaultGrant",
            kind: ValueKind::ClosedList(crate::node_store::NODE_CAPABILITIES),
            summary: "Capabilities a node is granted when it first becomes verified.",
            read: |c| c.pairing.default_grant.clone(),
        }],
    },
    SectionSpec {
        name: "upkeep",
        summary: "The check lane's own intent.",
        keys: &[KeySpec {
            name: "verifyCommand",
            kind: ValueKind::Scalar,
            summary: "Shell command the check lane runs at SessionStart/Stop to verify the working tree. Empty disables the lane.",
            read: |c| vec![c.upkeep.verify_command.clone()],
        }],
    },
];

/// Every settable key as an operator types it (`<section>.<key>`), in table
/// order — derived from [`SCHEMA`], so a listing can never disagree with what
/// actually exists.
pub fn keys() -> Vec<String> {
    SCHEMA
        .iter()
        .flat_map(|s| s.keys.iter().map(move |k| format!("{}.{}", s.name, k.name)))
        .collect()
}

/// Resolve a dotted `<section>.<key>` against [`SCHEMA`].
pub fn lookup(dotted: &str) -> Option<(&'static SectionSpec, &'static KeySpec)> {
    let (section, key) = dotted.split_once('.')?;
    let s = SCHEMA.iter().find(|s| s.name == section)?;
    let k = s.keys.iter().find(|k| k.name == key)?;
    Some((s, k))
}

// ── Resolution ──────────────────────────────────────────────────────────────

/// Where the config comes from, and whether this instance may write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub path: PathBuf,
    /// `true` when [`ENV_CONFIG`] pointed here — an externally rendered file
    /// (the nix store path) that [`set`] refuses to write.
    pub managed: bool,
}

/// Resolve the config path without reading it. See the module doc for the two
/// tiers; a relative or empty [`ENV_CONFIG`] is ignored outright rather than
/// resolved against the cwd.
pub fn source() -> Source {
    if let Ok(raw) = std::env::var(ENV_CONFIG) {
        let p = PathBuf::from(&raw);
        if p.is_absolute() {
            return Source { path: p, managed: true };
        }
    }
    Source { path: crate::fs::root().join(CONFIG_FILE), managed: false }
}

/// A resolved config plus where it came from — what `aoide config` prints and
/// what every future consumer reads.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub config: Config,
    pub path: PathBuf,
    pub managed: bool,
    /// Did the file actually exist? `false` means every value below is a
    /// default (never an error, see the module doc).
    pub present: bool,
}

/// Why a config that EXISTS could not be honoured. Never a missing file —
/// that is defaults, not a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The file is there but unreadable (permissions, a directory, an I/O
    /// fault).
    Unreadable { path: PathBuf, detail: String },
    /// Malformed TOML, an unknown key or section, or a value of the wrong
    /// type. `detail` carries the parser's own message, which names the
    /// offending key and where it sits.
    Malformed { path: PathBuf, detail: String },
    /// Well-formed, but a value falls outside its [`ValueKind`] vocabulary.
    /// Refused for the same reason an unknown key is: this file carries
    /// grants.
    InvalidValue { path: PathBuf, key: String, detail: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Unreadable { path, detail } | LoadError::Malformed { path, detail } => {
                write!(f, "{}: {detail}", path.display())
            }
            LoadError::InvalidValue { path, key, detail } => {
                write!(f, "{}: {key}: {detail}", path.display())
            }
        }
    }
}

impl LoadError {
    /// The file the error is about — every variant names one.
    pub fn path(&self) -> &Path {
        match self {
            LoadError::Unreadable { path, .. }
            | LoadError::Malformed { path, .. }
            | LoadError::InvalidValue { path, .. } => path,
        }
    }
}

/// Parse and validate config text. Pure — no path resolution, no I/O — so the
/// schema's own refusals are testable without a filesystem, and so [`set`] can
/// re-check the document it is about to write through the identical gate the
/// next [`load`] will apply.
pub fn parse(text: &str, path: &Path) -> Result<Config, LoadError> {
    let config: Config = toml::from_str(text)
        .map_err(|e| LoadError::Malformed { path: path.to_path_buf(), detail: e.to_string() })?;
    validate(&config, path)?;
    Ok(config)
}

/// Value-level validation, walked off [`SCHEMA`]: serde's `deny_unknown_fields`
/// answers "is this key real", this answers "is this value allowed". Also
/// validates [`Config::mesh`] — NOT part of [`SCHEMA`] (module doc), but not
/// exempt from failing loudly either.
pub fn validate(config: &Config, path: &Path) -> Result<(), LoadError> {
    for section in SCHEMA {
        for key in section.keys {
            let ValueKind::ClosedList(vocabulary) = key.kind else {
                // Scalar: any string is valid — there is no vocabulary to
                // check against (the module doc's whole reason this variant
                // exists).
                continue;
            };
            for element in (key.read)(config) {
                if !vocabulary.contains(&element.as_str()) {
                    return Err(LoadError::InvalidValue {
                        path: path.to_path_buf(),
                        key: format!("{}.{}", section.name, key.name),
                        detail: unknown_element(&element, vocabulary),
                    });
                }
            }
        }
    }
    validate_mesh(&config.mesh, path)
}

/// [`Config::mesh`]'s own pass: a mesh name and every node name inside it
/// must be [`crate::node_store::valid_node_name`]-shaped (a mesh name is
/// typed at a command line as `mesh pair <mesh>`, and a node name is joined
/// into `state/nodes.json` lookups the same way `node add`'s already is);
/// every hop must parse through [`crate::tunnel::parse_via`], whose own
/// message becomes the detail; every `grant` element must be in
/// [`crate::node_store::NODE_CAPABILITIES`], the same closed vocabulary
/// `pairing.defaultGrant` uses. Phase 1 has one global node namespace
/// (`state/nodes.json` is keyed by name alone), so a node name declared in
/// two meshes is an unresolvable declaration and is refused, naming both.
fn validate_mesh(mesh: &BTreeMap<String, Mesh>, path: &Path) -> Result<(), LoadError> {
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, m) in mesh {
        if !crate::node_store::valid_node_name(name) {
            return Err(LoadError::InvalidValue {
                path: path.to_path_buf(),
                key: format!("mesh.{name}"),
                detail: format!(
                    "`{name}` is not a valid mesh name — expected the same shape a node nickname \
                     takes: lowercase letters, digits, and `-`, starting with a letter or digit"
                ),
            });
        }
        if let Some(grant) = &m.grant {
            for cap in grant {
                if !crate::node_store::NODE_CAPABILITIES.contains(&cap.as_str()) {
                    return Err(LoadError::InvalidValue {
                        path: path.to_path_buf(),
                        key: format!("mesh.{name}.grant"),
                        detail: unknown_element(cap, crate::node_store::NODE_CAPABILITIES),
                    });
                }
            }
        }
        for (node, hop) in &m.nodes {
            if !crate::node_store::valid_node_name(node) {
                return Err(LoadError::InvalidValue {
                    path: path.to_path_buf(),
                    key: format!("mesh.{name}.nodes.{node}"),
                    detail: format!(
                        "`{node}` is not a valid node name — expected lowercase letters, digits, \
                         and `-`, starting with a letter or digit"
                    ),
                });
            }
            if let Err(detail) = crate::tunnel::parse_via(hop) {
                return Err(LoadError::InvalidValue {
                    path: path.to_path_buf(),
                    key: format!("mesh.{name}.nodes.{node}"),
                    detail,
                });
            }
            if let Some(&first) = owner.get(node.as_str()) {
                return Err(LoadError::InvalidValue {
                    path: path.to_path_buf(),
                    key: format!("mesh.{name}.nodes.{node}"),
                    detail: format!(
                        "`{node}` is declared in both `mesh.{first}` and `mesh.{name}` — a node \
                         name must be unique across every declared mesh"
                    ),
                });
            }
            owner.insert(node.as_str(), name.as_str());
        }
    }
    Ok(())
}

/// Load the effective config: [`source`]'s path, parsed and validated, or all
/// defaults when the file is absent.
pub fn load() -> Result<Loaded, LoadError> {
    let Source { path, managed } = source();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Loaded { config: Config::default(), path, managed, present: false });
        }
        Err(e) => return Err(LoadError::Unreadable { path, detail: e.to_string() }),
    };
    let config = parse(&text, &path)?;
    Ok(Loaded { config, path, managed, present: true })
}

// ── Values ──────────────────────────────────────────────────────────────────

/// Read a typed value off a command line, per the key's [`ValueKind`]. A
/// [`ValueKind::Scalar`] is never comma-split — the raw string IS the value,
/// whatever it contains (a verify command is one shell line, commas and all).
pub fn parse_value(kind: &ValueKind, raw: &str) -> Result<Vec<String>, String> {
    let vocabulary = match kind {
        ValueKind::ClosedList(v) => v,
        ValueKind::Scalar => return Ok(vec![raw.to_string()]),
    };
    if raw.trim().is_empty() {
        // "Grant nothing" is a real intent, not a typo.
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for part in raw.split(',') {
        let element = part.trim();
        if element.is_empty() {
            return Err(format!(
                "empty element in `{raw}` — pass a comma-separated list like `{}`",
                vocabulary.join(",")
            ));
        }
        if !vocabulary.contains(&element) {
            return Err(unknown_element(element, vocabulary));
        }
        if !values.iter().any(|v| v == element) {
            values.push(element.to_string());
        }
    }
    Ok(values)
}

/// Escape a value for DISPLAY as a TOML basic string (backslash, then quote —
/// the two characters a basic string cannot carry literally). Display only:
/// the file itself is always written through `toml_edit` (`set`, below),
/// which does its own correct escaping independently of this — this
/// function exists solely so [`render_value`]'s output (`aoide config`'s
/// listing, `set`'s own confirmation line) never LIES about what a value
/// holds. A verify command containing a literal `"` (`sh -c "make check"`
/// is an ordinary shape) is exactly the case a naive `format!("\"{v}\"")`
/// renders as broken-looking, ambiguous text.
fn escape_toml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// A value as it reads in the file — the same rendering `aoide config`
/// prints. A [`ValueKind::Scalar`] renders as a bare TOML string, never an
/// array of one.
pub fn render_value(kind: &ValueKind, value: &[String]) -> String {
    match kind {
        ValueKind::ClosedList(_) => format!(
            "[{}]",
            value
                .iter()
                .map(|v| format!("\"{}\"", escape_toml_string(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ValueKind::Scalar => {
            format!("\"{}\"", escape_toml_string(value.first().map(String::as_str).unwrap_or("")))
        }
    }
}

fn unknown_element(element: &str, vocabulary: &[&str]) -> String {
    format!("`{element}` is not one of {}", vocabulary.join(", "))
}

// ── The write half (`aoide config set`) ─────────────────────────────────────

/// Why a [`set`] was refused. Every variant carries what a taught error needs
/// to say, and nothing is written in any of these cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetRefusal {
    /// [`ENV_CONFIG`] points at this file, so something else renders it.
    Managed { path: PathBuf },
    /// Unmanaged, but this uid cannot write it (a read-only file, a read-only
    /// directory, a read-only filesystem).
    Unwritable { path: PathBuf, detail: String },
    /// No such key in [`SCHEMA`].
    UnknownKey { key: String },
    /// Known key, unusable value.
    BadValue { key: String, detail: String },
    /// The config already on disk cannot be understood, so this write would be
    /// building on sand. Refused before anything is touched.
    Unloadable { detail: String },
    /// The write itself failed.
    Io { path: PathBuf, detail: String },
}

impl std::fmt::Display for SetRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SetRefusal::Managed { path } => write!(
                f,
                "{} is a MANAGED config — ${ENV_CONFIG} points at it, so it is rendered read-only by something else (on NixOS: set `aoide.config` in your host configuration and rebuild). `aoide config set` never writes a managed config. To keep this host's config editable instead, unset ${ENV_CONFIG} and edit {}",
                path.display(),
                crate::fs::root().join(CONFIG_FILE).display()
            ),
            SetRefusal::Unwritable { path, detail } => write!(
                f,
                "{} is not writable by this user ({detail}) — fix its permissions, or point ${ENV_CONFIG} at a config you render elsewhere",
                path.display()
            ),
            SetRefusal::UnknownKey { key } => {
                write!(
                    f,
                    "`{key}` is not a settable config key — known keys are {}",
                    keys().join(", ")
                )
            }
            SetRefusal::BadValue { key, detail } => write!(f, "{key}: {detail}"),
            SetRefusal::Unloadable { detail } => {
                write!(f, "refusing to write on top of a config that does not load: {detail}")
            }
            SetRefusal::Io { path, detail } => write!(f, "{}: {detail}", path.display()),
        }
    }
}

/// What a successful [`set`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetOutcome {
    pub path: PathBuf,
    pub key: String,
    /// The value as it now reads in the file.
    pub value: String,
    /// `false` when the key already held exactly this value — the file was
    /// still rewritten, but nothing about the effective config moved.
    pub changed: bool,
    /// Did this call create the file?
    pub created: bool,
}

/// Set one `<section>.<key>` to `raw`, schema-validated, atomically, in place.
///
/// In-place matters: the edit runs through `toml_edit` on the file's own text,
/// so the comments an operator wrote next to a grant survive a write that a
/// serialize-the-whole-struct round trip would erase — the exact property TOML
/// was chosen for.
///
/// Nothing is written until every check passes: the config must be unmanaged,
/// the key known to [`SCHEMA`], the value inside its vocabulary, and the
/// config ALREADY on disk loadable. The rewritten document is then re-parsed
/// through [`parse`] before it is committed, so a write can never leave behind
/// a file the next [`load`] would refuse.
pub fn set(key: &str, raw: &str) -> Result<SetOutcome, SetRefusal> {
    let Source { path, managed } = source();
    if managed {
        return Err(SetRefusal::Managed { path });
    }
    let Some((section, spec)) = lookup(key) else {
        return Err(SetRefusal::UnknownKey { key: key.to_string() });
    };

    let (existing_text, created) = match std::fs::read_to_string(&path) {
        Ok(t) => (t, false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), true),
        Err(e) => return Err(SetRefusal::Unwritable { path, detail: e.to_string() }),
    };
    let before =
        parse(&existing_text, &path).map_err(|e| SetRefusal::Unloadable { detail: e.to_string() })?;
    let mut doc = existing_text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| SetRefusal::Unloadable { detail: format!("{}: {e}", path.display()) })?;

    let value = parse_value(&spec.kind, raw)
        .map_err(|detail| SetRefusal::BadValue { key: key.to_string(), detail })?;
    // A section the file does not carry yet is created as a REAL `[section]`
    // header, never the inline `section = { key = ... }` an implicitly-created
    // table renders as. Same shape the nix front-end renders and the same shape
    // the schema documents — this is the one file a human edits, so the first
    // `set` has to leave behind something they would have written themselves.
    if doc.get(section.name).is_none() {
        let mut table = toml_edit::Table::new();
        table.set_implicit(false);
        doc.insert(section.name, toml_edit::Item::Table(table));
    }
    match spec.kind {
        ValueKind::ClosedList(_) => {
            let mut array = toml_edit::Array::new();
            for element in &value {
                array.push(element.as_str());
            }
            doc[section.name][spec.name] = toml_edit::value(array);
        }
        ValueKind::Scalar => {
            let scalar = value.first().map(String::as_str).unwrap_or("");
            doc[section.name][spec.name] = toml_edit::value(scalar);
        }
    }

    let text = doc.to_string();
    let after = parse(&text, &path)
        .map_err(|e| SetRefusal::BadValue { key: key.to_string(), detail: e.to_string() })?;

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return Err(SetRefusal::Unwritable { path, detail: e.to_string() });
        }
    }
    if let Err(e) = crate::fs::atomic_write(&path, &text) {
        return Err(match e.kind() {
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem => {
                SetRefusal::Unwritable { path, detail: e.to_string() }
            }
            _ => SetRefusal::Io { path, detail: e.to_string() },
        });
    }

    Ok(SetOutcome {
        path,
        key: key.to_string(),
        value: render_value(&spec.kind, &value),
        changed: before != after,
        created,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Point `$AOIDE_ROOT` at a fresh temp dir (and clear `$AOIDE_CONFIG`) for
    /// one closure — process-env mutation, so serialized on the shared env
    /// lock like every other env-touching test in this crate.
    fn with_temp_root<F: FnOnce(&Path)>(tag: &str, f: F) {
        let _guard = crate::env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "aoide-config-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let saved_root = std::env::var("AOIDE_ROOT").ok();
        let saved_config = std::env::var(ENV_CONFIG).ok();
        std::env::set_var("AOIDE_ROOT", &dir);
        std::env::remove_var(ENV_CONFIG);
        f(&dir);
        match saved_root {
            Some(v) => std::env::set_var("AOIDE_ROOT", v),
            None => std::env::remove_var("AOIDE_ROOT"),
        }
        match saved_config {
            Some(v) => std::env::set_var(ENV_CONFIG, v),
            None => std::env::remove_var(ENV_CONFIG),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn probe() -> PathBuf {
        PathBuf::from("/probe/config.toml")
    }

    // ── The table ───────────────────────────────────────────────────────────

    #[test]
    fn every_table_row_reads_a_real_field_and_closed_list_defaults_are_inside_their_own_vocabulary() {
        let defaults = Config::default();
        assert!(!SCHEMA.is_empty());
        for section in SCHEMA {
            for key in section.keys {
                let ValueKind::ClosedList(vocabulary) = key.kind else {
                    // Scalar: nothing to check against — every string is valid.
                    continue;
                };
                assert!(!vocabulary.is_empty(), "{}.{} has an empty vocabulary", section.name, key.name);
                for element in (key.read)(&defaults) {
                    assert!(
                        vocabulary.contains(&element.as_str()),
                        "{}.{}'s own default `{element}` is outside its vocabulary",
                        section.name,
                        key.name
                    );
                }
            }
        }
    }

    #[test]
    fn the_key_listing_and_the_lookup_agree_with_the_table() {
        assert_eq!(
            keys(),
            vec!["pairing.defaultGrant".to_string(), "upkeep.verifyCommand".to_string()]
        );
        for dotted in keys() {
            assert!(lookup(&dotted).is_some(), "{dotted} lists but does not resolve");
        }
        assert!(lookup("pairing").is_none(), "a bare section is not a key");
        assert!(lookup("pairing.nope").is_none());
        assert!(lookup("nope.defaultGrant").is_none());
    }

    #[test]
    fn the_pairing_vocabulary_is_the_one_node_allow_already_enforces() {
        let (_, spec) = lookup("pairing.defaultGrant").unwrap();
        let ValueKind::ClosedList(vocabulary) = spec.kind else {
            panic!("pairing.defaultGrant must stay a ClosedList");
        };
        assert_eq!(vocabulary, crate::node_store::NODE_CAPABILITIES);
    }

    #[test]
    fn the_verify_command_is_a_scalar_with_no_vocabulary_to_check() {
        let (_, spec) = lookup("upkeep.verifyCommand").unwrap();
        assert_eq!(spec.kind, ValueKind::Scalar);
    }

    // ── Schema ──────────────────────────────────────────────────────────────

    #[test]
    fn an_empty_document_is_every_default() {
        assert_eq!(parse("", &probe()).unwrap(), Config::default());
        assert_eq!(Config::default().pairing.default_grant, vec!["read".to_string()]);
        assert_eq!(Config::default().upkeep.verify_command, "", "the lane is off until configured");
    }

    #[test]
    fn a_verify_command_round_trips_commas_spaces_and_all() {
        // A scalar is never comma-split — a real verify command is one shell
        // line that may itself contain commas.
        let c = parse(
            "[upkeep]\nverifyCommand = \"nix build --no-link .#checks.x86_64-linux.{fmt,nix-lint}\"\n",
            &probe(),
        )
        .unwrap();
        assert_eq!(
            c.upkeep.verify_command,
            "nix build --no-link .#checks.x86_64-linux.{fmt,nix-lint}"
        );
    }

    #[test]
    fn a_section_present_but_empty_still_defaults_its_keys() {
        let c = parse("[pairing]\n", &probe()).unwrap();
        assert_eq!(c.pairing.default_grant, vec!["read".to_string()]);
    }

    #[test]
    fn a_real_value_round_trips() {
        let c = parse("[pairing]\ndefaultGrant = [\"read\", \"spawn\"]\n", &probe()).unwrap();
        assert_eq!(c.pairing.default_grant, vec!["read".to_string(), "spawn".to_string()]);
    }

    #[test]
    fn an_unknown_key_fails_loudly_and_names_itself() {
        let err = parse("[pairing]\ndefualtGrant = [\"read\"]\n", &probe()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::Malformed { .. }), "{msg}");
        assert!(msg.contains("defualtGrant"), "the offending key must be named: {msg}");
    }

    #[test]
    fn an_unknown_section_fails_loudly_and_names_itself() {
        // `[mesh]` is a KNOWN section as of task #135 P4 — this probe moved
        // to a section that stays unknown either way, so it still proves
        // `deny_unknown_fields` refuses a typo'd top-level section by name.
        let err = parse("[nosuchsection]\nseeds = []\n", &probe()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::Malformed { .. }), "{msg}");
        assert!(msg.contains("nosuchsection"), "the offending section must be named: {msg}");
    }

    #[test]
    fn a_known_mesh_section_with_an_unknown_key_still_fails_by_name() {
        let err = parse("[mesh.home]\nbogus = true\n", &probe()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::Malformed { .. }), "{msg}");
        assert!(msg.contains("bogus"), "the offending key must be named: {msg}");
    }

    #[test]
    fn a_wrong_typed_value_fails_loudly() {
        let err = parse("[pairing]\ndefaultGrant = \"read\"\n", &probe()).unwrap_err();
        assert!(matches!(err, LoadError::Malformed { .. }), "{err}");
    }

    #[test]
    fn an_unknown_capability_is_refused_by_value_not_by_key() {
        let err = parse("[pairing]\ndefaultGrant = [\"read\", \"root\"]\n", &probe()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::InvalidValue { .. }), "{msg}");
        assert!(msg.contains("root"), "{msg}");
        assert!(msg.contains("pairing.defaultGrant"), "{msg}");
    }

    // ── `[mesh.*]` (task #135 P4) ──────────────────────────────────────────

    #[test]
    fn a_full_mesh_document_round_trips() {
        let c = parse(
            "[mesh.home]\n\
             grant = [\"read\", \"spawn\"]\n\
             sameOperator = true\n\
             [mesh.home.nodes]\n\
             sakaki = \"ssh://khoa@192.168.1.202\"\n\
             chiyo = \"ssh://khoa@192.168.1.186\"\n",
            &probe(),
        )
        .unwrap();
        let home = c.mesh.get("home").expect("mesh.home must parse");
        assert_eq!(home.grant, Some(vec!["read".to_string(), "spawn".to_string()]));
        assert!(home.same_operator);
        assert_eq!(home.nodes.get("sakaki").map(String::as_str), Some("ssh://khoa@192.168.1.202"));
        assert_eq!(home.nodes.get("chiyo").map(String::as_str), Some("ssh://khoa@192.168.1.186"));
    }

    #[test]
    fn a_mesh_with_no_optional_keys_defaults_grant_and_same_operator() {
        let c = parse(
            "[mesh.home.nodes]\nsakaki = \"ssh://khoa@192.168.1.202\"\n",
            &probe(),
        )
        .unwrap();
        let home = &c.mesh["home"];
        assert_eq!(home.grant, None, "absent grant parses as None — nothing at this layer substitutes pairing.defaultGrant");
        assert!(!home.same_operator);
    }

    #[test]
    fn a_malformed_hop_is_invalid_value_naming_the_node_and_carrying_parse_vias_message() {
        let err = parse(
            "[mesh.home.nodes]\nsakaki = \"not-a-hop\"\n",
            &probe(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::InvalidValue { .. }), "{msg}");
        assert!(msg.contains("mesh.home.nodes.sakaki"), "{msg}");
        assert!(
            msg.contains(&crate::tunnel::parse_via("not-a-hop").unwrap_err()),
            "the detail must be parse_via's own message: {msg}"
        );
    }

    #[test]
    fn a_mesh_grant_outside_the_capability_vocabulary_is_invalid_value_naming_the_element() {
        let err = parse(
            "[mesh.home]\ngrant = [\"read\", \"root\"]\n[mesh.home.nodes]\n",
            &probe(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::InvalidValue { .. }), "{msg}");
        assert!(msg.contains("root"), "{msg}");
        assert!(msg.contains("mesh.home.grant"), "{msg}");
    }

    #[test]
    fn an_invalid_mesh_name_is_refused() {
        let err = parse("[mesh.\"Not Valid\".nodes]\n", &probe()).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::InvalidValue { .. }), "{msg}");
        assert!(msg.contains("Not Valid"), "{msg}");
    }

    #[test]
    fn an_invalid_node_name_inside_a_mesh_is_refused() {
        let err = parse(
            "[mesh.home.nodes]\n\"Not Valid\" = \"ssh://khoa@192.168.1.202\"\n",
            &probe(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::InvalidValue { .. }), "{msg}");
        assert!(msg.contains("Not Valid"), "{msg}");
    }

    #[test]
    fn one_node_name_declared_in_two_meshes_is_refused_naming_both() {
        let err = parse(
            "[mesh.home.nodes]\nsakaki = \"ssh://khoa@192.168.1.202\"\n\
             [mesh.away.nodes]\nsakaki = \"ssh://khoa@10.0.0.5\"\n",
            &probe(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LoadError::InvalidValue { .. }), "{msg}");
        assert!(msg.contains("home"), "{msg}");
        assert!(msg.contains("away"), "{msg}");
        assert!(msg.contains("sakaki"), "{msg}");
    }

    #[test]
    fn a_config_with_no_mesh_section_is_byte_identical_to_the_pre_p4_default() {
        let c = parse("[pairing]\ndefaultGrant = [\"read\"]\n", &probe()).unwrap();
        assert!(c.mesh.is_empty());
        assert_eq!(c, Config { mesh: BTreeMap::new(), ..c.clone() });
    }

    #[test]
    fn config_set_refuses_a_mesh_key_as_not_settable() {
        with_temp_root("mesh-not-settable", |_| {
            let err = set("mesh.home.nodes.sakaki", "ssh://khoa@192.168.1.202").unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, SetRefusal::UnknownKey { .. }), "{msg}");
            assert!(msg.contains("not a settable config key"), "{msg}");
        });
    }

    // ── Resolution ──────────────────────────────────────────────────────────

    #[test]
    fn a_missing_file_is_all_defaults_never_an_error() {
        with_temp_root("missing", |dir| {
            let loaded = load().expect("a missing config is defaults, not a failure");
            assert_eq!(loaded.config, Config::default());
            assert_eq!(loaded.path, dir.join(CONFIG_FILE));
            assert!(!loaded.managed);
            assert!(!loaded.present);
        });
    }

    #[test]
    fn the_env_pointer_wins_and_marks_the_config_managed() {
        with_temp_root("managed", |dir| {
            let elsewhere = dir.join("rendered.toml");
            std::fs::write(&elsewhere, "[pairing]\ndefaultGrant = [\"read\", \"spawn\"]\n").unwrap();
            std::env::set_var(ENV_CONFIG, &elsewhere);
            let loaded = load().unwrap();
            assert_eq!(loaded.path, elsewhere);
            assert!(loaded.managed);
            assert!(loaded.present);
            assert_eq!(
                loaded.config.pairing.default_grant,
                vec!["read".to_string(), "spawn".to_string()]
            );
        });
    }

    #[test]
    fn a_relative_env_pointer_is_ignored_the_way_every_other_override_is() {
        with_temp_root("relative", |dir| {
            std::env::set_var(ENV_CONFIG, "config.toml");
            let s = source();
            assert_eq!(s.path, dir.join(CONFIG_FILE));
            assert!(!s.managed);
        });
    }

    // ── The write half ──────────────────────────────────────────────────────

    #[test]
    fn set_creates_the_file_and_the_value_reads_back() {
        with_temp_root("create", |dir| {
            let out = set("pairing.defaultGrant", "read,spawn").unwrap();
            assert!(out.created);
            assert!(out.changed);
            assert_eq!(out.path, dir.join(CONFIG_FILE));
            let loaded = load().unwrap();
            assert!(loaded.present);
            assert_eq!(
                loaded.config.pairing.default_grant,
                vec!["read".to_string(), "spawn".to_string()]
            );
            let text = std::fs::read_to_string(&out.path).unwrap();
            assert!(
                text.starts_with("[pairing]\n"),
                "a created file has to read like one a human would have written — \
                 a real section header, never an inline table: {text}"
            );
        });
    }

    #[test]
    fn set_preserves_the_comments_an_operator_wrote_beside_a_grant() {
        with_temp_root("comments", |dir| {
            let path = dir.join(CONFIG_FILE);
            std::fs::write(
                &path,
                "# read-only until the far box proves itself\n[pairing]\ndefaultGrant = [\"read\"]\n",
            )
            .unwrap();
            set("pairing.defaultGrant", "read,spawn").unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.contains("# read-only until the far box proves itself"),
                "a comment beside a grant is the whole reason this file is TOML: {text}"
            );
            assert!(text.contains("spawn"), "{text}");
        });
    }

    #[test]
    fn setting_the_same_value_twice_reports_unchanged() {
        with_temp_root("idempotent", |_| {
            set("pairing.defaultGrant", "read").unwrap();
            let again = set("pairing.defaultGrant", "read").unwrap();
            assert!(!again.changed);
            assert!(!again.created);
        });
    }

    #[test]
    fn set_refuses_a_managed_config_and_names_the_real_path() {
        with_temp_root("refuse-managed", |dir| {
            let elsewhere = dir.join("rendered.toml");
            std::fs::write(&elsewhere, "[pairing]\ndefaultGrant = [\"read\"]\n").unwrap();
            std::env::set_var(ENV_CONFIG, &elsewhere);
            let err = set("pairing.defaultGrant", "spawn").unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, SetRefusal::Managed { .. }), "{msg}");
            assert!(msg.contains(&elsewhere.display().to_string()), "{msg}");
            assert!(msg.contains(ENV_CONFIG), "{msg}");
            assert_eq!(
                std::fs::read_to_string(&elsewhere).unwrap(),
                "[pairing]\ndefaultGrant = [\"read\"]\n",
                "a refused set never touches the managed file"
            );
        });
    }

    #[test]
    fn set_refuses_an_unknown_key_and_lists_the_known_ones() {
        with_temp_root("unknown-key", |dir| {
            let err = set("pairing.defualtGrant", "read").unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, SetRefusal::UnknownKey { .. }), "{msg}");
            assert!(msg.contains("pairing.defaultGrant"), "{msg}");
            assert!(!dir.join(CONFIG_FILE).exists(), "a refused set never creates the file");
        });
    }

    #[test]
    fn set_refuses_an_unknown_capability() {
        with_temp_root("bad-value", |dir| {
            let err = set("pairing.defaultGrant", "read,root").unwrap_err();
            let msg = err.to_string();
            assert!(matches!(err, SetRefusal::BadValue { .. }), "{msg}");
            assert!(msg.contains("root"), "{msg}");
            assert!(!dir.join(CONFIG_FILE).exists(), "a refused set never creates the file");
        });
    }

    #[test]
    fn set_refuses_to_write_on_top_of_a_config_that_does_not_load() {
        with_temp_root("unloadable", |dir| {
            let path = dir.join(CONFIG_FILE);
            // `[mesh]` became a KNOWN section at task #135 P4 — this probe
            // uses a section that stays unknown either way, since this test
            // is about the "already-on-disk config fails to load" refusal,
            // not about `[mesh]` specifically.
            std::fs::write(&path, "[nosuchsection]\nseeds = []\n").unwrap();
            let err = set("pairing.defaultGrant", "read").unwrap_err();
            assert!(matches!(err, SetRefusal::Unloadable { .. }), "{err}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "[nosuchsection]\nseeds = []\n",
                "the unreadable config is left exactly as it was"
            );
        });
    }

    #[test]
    fn set_refuses_an_unwritable_config_without_touching_it() {
        with_temp_root("unwritable", |dir| {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.join(CONFIG_FILE);
            std::fs::write(&path, "[pairing]\ndefaultGrant = [\"read\"]\n").unwrap();
            // The atomic write renames a temp INTO the directory, so the
            // directory's mode is what decides writability, not the file's.
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let refusal = set("pairing.defaultGrant", "spawn");
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let err = refusal.expect_err("a read-only directory must refuse, never half-write");
            assert!(matches!(err, SetRefusal::Unwritable { .. }), "{err}");
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "[pairing]\ndefaultGrant = [\"read\"]\n"
            );
        });
    }

    #[test]
    fn an_empty_value_is_a_real_intent_not_a_typo() {
        with_temp_root("empty-grant", |_| {
            set("pairing.defaultGrant", "").unwrap();
            assert!(load().unwrap().config.pairing.default_grant.is_empty());
        });
    }

    #[test]
    fn a_repeated_element_collapses_rather_than_duplicating() {
        let (_, spec) = lookup("pairing.defaultGrant").unwrap();
        assert_eq!(parse_value(&spec.kind, "read, read ,spawn").unwrap(), vec!["read", "spawn"]);
    }

    #[test]
    fn render_value_matches_what_the_file_holds() {
        let list = ValueKind::ClosedList(&[]);
        assert_eq!(render_value(&list, &["read".to_string()]), "[\"read\"]");
        assert_eq!(render_value(&list, &[]), "[]");
        assert_eq!(render_value(&ValueKind::Scalar, &["cargo test".to_string()]), "\"cargo test\"");
    }

    #[test]
    fn render_value_escapes_a_literal_quote_instead_of_rendering_a_lie() {
        // Review finding: `sh -c "make check"`-shaped commands are ordinary,
        // and an unescaped render used to produce
        // `"sh -c "make check""` — text that does not even round-trip as one
        // TOML string. This is a DISPLAY fix only: the file itself is never
        // affected (`set_writes_and_reads_back_a_verify_command...` below
        // proves the actual write/read round trip separately).
        let escaped = render_value(&ValueKind::Scalar, &["sh -c \"make check\"".to_string()]);
        assert_eq!(escaped, "\"sh -c \\\"make check\\\"\"");
    }

    // ── The verify command, end to end ─────────────────────────────────────

    #[test]
    fn set_writes_and_reads_back_a_verify_command_as_a_bare_toml_string_not_an_array_of_one() {
        with_temp_root("verify-set", |dir| {
            let out = set("upkeep.verifyCommand", "nix flake check").unwrap();
            assert!(out.created);
            assert!(out.changed);
            assert_eq!(out.value, "\"nix flake check\"");
            let text = std::fs::read_to_string(dir.join(CONFIG_FILE)).unwrap();
            assert!(
                text.contains("verifyCommand = \"nix flake check\""),
                "a scalar must render as a bare string, never `[\"nix flake check\"]`: {text}"
            );
            let loaded = load().unwrap();
            assert_eq!(loaded.config.upkeep.verify_command, "nix flake check");
        });
    }

    #[test]
    fn set_confirmation_line_escapes_a_verify_command_containing_a_literal_quote() {
        with_temp_root("verify-quote", |_| {
            let out = set("upkeep.verifyCommand", "sh -c \"make check\"").unwrap();
            // The CONFIRMATION line (what an operator actually reads back) is
            // escaped, not the broken `"sh -c "make check""` a naive render
            // used to produce.
            assert_eq!(out.value, "\"sh -c \\\"make check\\\"\"");
            // The FILE itself round-trips correctly regardless — `toml_edit`
            // did its own correct escaping the whole time; this was always a
            // display-only bug.
            assert_eq!(load().unwrap().config.upkeep.verify_command, "sh -c \"make check\"");
        });
    }

    #[test]
    fn setting_the_verify_command_to_empty_disables_the_lane_and_is_a_real_intent() {
        with_temp_root("verify-empty", |_| {
            set("upkeep.verifyCommand", "cargo test").unwrap();
            let out = set("upkeep.verifyCommand", "").unwrap();
            assert!(out.changed);
            assert_eq!(load().unwrap().config.upkeep.verify_command, "");
        });
    }
}
