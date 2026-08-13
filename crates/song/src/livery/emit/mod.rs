//! The emitter registry — one trait, one registry, one additive backend
//! pattern (the "apply a theme to ANY settings system" requirement made
//! structural).
//!
//! All emitters consume the SAME fully-resolved note set from
//! `crate::livery::resolve`, so the live targets can never disagree. A new
//! backend is ONE `emit/<name>.rs` + one line in [`registry`] — the same
//! additive discipline as pkgs walker / dendrites / song widgets.
//!
//! Pure emit vs. host apply stays split (the seam PACKAGE-LAYOUT.md already
//! draws inside song): these emitters only PRODUCE bytes;
//! `live::apply_live` / `shellbridge::atomic_write` are the effectful half
//! that consumes them. `gtk`/`gsettings` host-mutating apply belongs to the
//! deferred `management` seam, not this registry.

use crate::livery::emit::file::FileTemplate;
use crate::livery::emit::hyprctl::Hyprctl;
use crate::livery::emit::osc::Osc;
use crate::livery::emit::stage::Stage;
use crate::livery::resolve::Resolved;
use std::fmt;

pub mod file;
pub mod hyprctl;
pub mod osc;
pub mod stage;

/// A structured engine error (validation failures, deref failures, emitter
/// misuse). Never a panic — the CLI maps it to an exit-1 envelope.
#[derive(Debug, Clone)]
pub struct EmitError {
    pub message: String,
}

impl EmitError {
    pub fn new(message: impl Into<String>) -> Self {
        EmitError {
            message: message.into(),
        }
    }
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EmitError {}

/// What one emitter produced — the three output shapes the backends need.
#[derive(Debug, Clone, PartialEq)]
pub enum EmitOutput {
    /// A JSON document (the stage file for Quickshell).
    Json(serde_json::Value),
    /// Shell-ready argv lines (`hyprctl keyword …`); the CLI quotes/joins
    /// them one per line, like the Node engine's `shellQuote` join.
    Lines(Vec<Vec<String>>),
    /// A raw byte stream (terminal OSC sequences, file-template render).
    Text(String),
}

/// Per-call emitter options. Only the `file` backend reads `template` today;
/// a future backend adds its field here (the struct is additive).
#[derive(Debug, Default, Clone, Copy)]
pub struct EmitOpts<'a> {
    pub template: Option<&'a str>,
}

/// One emit backend. `Sync` so the static registry is `&'static dyn Emitter`.
pub trait Emitter: Sync {
    /// The CLI-facing target name: `"stage" | "hyprctl" | "osc" | "file"`.
    fn target(&self) -> &'static str;
    /// Produce the output for one fully-resolved note set.
    fn emit(&self, r: &Resolved, o: &EmitOpts) -> Result<EmitOutput, EmitError>;
}

/// The full backend registry, in a fixed order (stage, hyprctl, osc, file).
pub fn registry() -> &'static [&'static dyn Emitter] {
    &[&Stage, &Hyprctl, &Osc, &FileTemplate]
}

/// Look one backend up by its target name.
pub fn emitter(target: &str) -> Option<&'static dyn Emitter> {
    registry().iter().copied().find(|e| e.target() == target)
}
