//! The parsed invocation handed to the dispatcher.

use crate::audit::Door;
use std::collections::BTreeMap;

/// Parsed invocation handed to the dispatcher.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// Command path, e.g. `["rice", "gen"]`.
    pub path: Vec<String>,
    /// Positional args in order.
    pub args: Vec<String>,
    /// Named flags (`--foo bar`, or `--foo` → `"true"`).
    pub flags: BTreeMap<String, String>,
    /// Which door this came through (for the audit log).
    pub door: Door,
}

impl Invocation {
    pub fn flag_present(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }
    pub fn dotted(&self) -> String {
        self.path.join(".")
    }
}
