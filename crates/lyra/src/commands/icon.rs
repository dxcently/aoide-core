//! `lyra icon` — pack-independent widget icons, Iconify identifiers
//! (`<collection>:<name>`), resolved against a PINNED, hashed local copy of
//! each collection's IconifyJSON (`pkgs/iconify-data`) — never a network
//! fetch at render or resolve time (root `AGENTS.md` house rule 7: a
//! capability enters at one conventional path and is removable without a
//! trace; here that path is `--data <dir>`/`$AOIDE_ICON_DATA`, never a URL).
//!
//! Three commands (`design/p-icon-brief.md` §C1):
//! - `icon collections` — list the pinned collections (prefix, version,
//!   count, license, author) under the data directory.
//! - `icon list` — list/search one collection's icon (and alias) names.
//! - `icon resolve` — the only writer: turns a selection (bare
//!   `<collection>:<name>`/custom-asset identifiers, or a `--selection`
//!   manifest file of the same identifiers) into `<out>/<collection>/
//!   <name>.svg` + `<out>/custom/<slug>.<ext>` plus one `<out>/catalog.json`
//!   describing every resolved asset. Byte-diffed (a repeat resolve with
//!   nothing new is a true no-op, `commands::preview::handle_preview_declare`'s
//!   own discipline) and PRUNES any previously-generated asset the current
//!   selection no longer names (root `AGENTS.md` house rule 7).
//!
//! **Zero new Rust dependencies** (§C6): every IconifyJSON/catalog/selection
//! document is handled as a bare `serde_json::Value` — `Value`'s own
//! `Serialize`/`Deserialize` impls live inside `serde_json` itself, so no
//! typed struct (and therefore no `#[derive(Serialize/Deserialize)]`, which
//! would need a direct `serde` dependency this crate's `Cargo.toml` does not
//! carry) is needed anywhere in this module.
//!
//! **The assembly algorithm is a direct port**, not a reinterpretation, of
//! upstream Iconify's own `@iconify/utils` (`raw.githubusercontent.com/
//! iconify/iconify/main/packages/utils/src/`):
//! - alias-chain walk + property fold: `icon-set/get-icon.ts:12-32`
//!   (`internalGetIconData`/`getIconData`) + `icon/merge.ts:13-36`
//!   (`mergeIconData`) + `icon/transformations.ts:6-21`
//!   (`mergeIconTransformations`). [`resolve_icon_data`] computes the exact
//!   same result via one linear walk instead of upstream's pairwise
//!   recursive fold: for a NON-transform key (`body`/`left`/`top`/`width`/
//!   `height`), "child-wins-then-parent" applied all the way down a chain is
//!   just "the value closest to the requested name wins, the collection's
//!   own root fields are the final fallback" — there is no other order the
//!   pairwise fold can produce. For `hFlip`/`vFlip`/`rotate`, upstream's
//!   merge is a blind XOR/sum against a false/0 neutral element at every
//!   level (`icon/transformations.ts:11-19`), which is associative and
//!   commutative — folding pairwise inward from the leaf and summing the
//!   whole chain (plus the collection's own root transform fields) in one
//!   pass are the same computation.
//! - SVG assembly: `svg/build.ts:67-219` (`iconToSVG`) for the box/transform-
//!   string math, `svg/defs.ts` (`wrapSVGContent`/`splitSVGDefs`, imported at
//!   `svg/build.ts:7`) so a `<defs>` block (iconoir's `podcast` etc. use
//!   `<use href="#…">` against one) stays outside the `<g transform>` wrap,
//!   and `svg/html.ts` (`iconToHTML`) for the final `<svg …>` attribute
//!   order (`width`, `height`, `viewBox`, `xmlns:xlink` only if the body
//!   contains `xlink:`). ONE deliberate omission: `lyra icon resolve`
//!   exposes no caller-side size/rotate/flip override, so upstream's
//!   two-pass `[fullIcon, fullCustomisations].forEach` (`svg/build.ts:79`)
//!   degenerates to the single icon-owned pass here — the second pass is
//!   always the identity transform (no wrap, no box mutation) — and the
//!   emitted `width`/`height` attributes are the icon's own final box
//!   dimensions rather than upstream's `calculateSize`/`'1em'` fallback
//!   (`svg/build.ts:180-198`), which exists only to serve that omitted
//!   caller override.
//!
//! **A note on the brief's own paraphrase vs. the fetched source.**
//! `design/p-icon-brief.md` §B states the emitted `viewBox` "uses the
//! PRE-swap width/height" for an odd (90°/270°) rotation. Reading
//! `svg/build.ts` directly: the width/height swap (`:152-165`) runs INSIDE
//! the SAME transform pass that computes the rotate string, and `boxWidth`/
//! `boxHeight` (`:178`, feeding `viewBox` at `:214`) are captured strictly
//! AFTER that whole pass completes — i.e. POST-swap, matching what a
//! rotated non-square icon must show to render upright (swapping the
//! bounding box on a 90°/270° turn is the physically correct behavior).
//! [`transform_body`] below implements the fetched source (post-swap); ONLY
//! a hand-authored fixture can exercise this, since neither pinned
//! collection has a non-square icon or an aliased transform (§B's "Shape
//! facts") — flagged for the coordinator rather than silently resolved
//! either way.
//!
//! **mono vs. multicolor** (§C1) is decided once, at resolve time, by
//! [`detect_mono`]: every `fill=`/`stroke=`/`stop-color=` VALUE is
//! `currentColor`/`none`/a `url(#…)` reference, and no `<image>` tag is
//! present. A mono icon's emitted `<svg>` carries `color="#000000"` so Qt's
//! `currentColor` resolves deterministically (root brief §A's verified fact:
//! Qt defaults an unset `currentColor` to black anyway — this makes it
//! explicit rather than relying on that default).

use crate::dispatch::Invocation;
use crate::output::Outcome;
use crate::registry::{arg, cmd, flag, Registry};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

pub fn register(r: &mut Registry) {
    r.insert(cmd!(
        path: ["icon", "collections"],
        summary: "List every pinned Iconify icon collection under the icon data directory: prefix, declared name, version, icon count, license, author, and the collection's own data path.",
        args: [],
        flags: [flag!(
            "data",
            "string",
            "Icon data directory holding <prefix>/{icons,info,metadata}.json per collection (default: $AOIDE_ICON_DATA, else the `nix build .#iconify-data` result's share/iconify)."
        )],
        gated: false,
        implemented: true,
        handler: handle_collections,
    ));
    r.insert(cmd!(
        path: ["icon", "list"],
        summary: "List (and optionally search) the icon and alias names in one pinned collection.",
        args: [],
        flags: [
            flag!("collection", "string", "Collection prefix, e.g. `iconoir` (required)."),
            flag!("search", "string", "Case-insensitive substring filter over icon name and categories."),
            flag!("limit", "string", "Cap the returned `icons` list (default: unlimited; `matched` still reports the full filtered count)."),
            flag!(
                "data",
                "string",
                "Icon data directory (default: $AOIDE_ICON_DATA, else the `nix build .#iconify-data` result's share/iconify)."
            )
        ],
        gated: false,
        implemented: true,
        handler: handle_list,
    ));
    r.insert(cmd!(
        path: ["icon", "resolve"],
        summary: "Resolve one or more `<collection>:<name>` Iconify identifiers (or custom `file:<path>`/bare-path assets) into SVGs plus a catalog.json under --out. Byte-diffed (a repeat resolve with nothing new is a true no-op) and prunes assets the selection no longer names.",
        args: [arg!(
            "identifier",
            "string",
            false,
            "One or more `<collection>:<name>` Iconify identifiers, or `file:<path>`/a bare path containing `/` for a custom asset. Omit when using --selection."
        )],
        flags: [
            flag!("selection", "string", "Read the identifier set from a selection manifest file (the same {schemaVersion, icons} shape as catalog.json, generated keys omitted) instead of positional args."),
            flag!("out", "string", "Output directory for the generated SVGs/copies and catalog.json (required)."),
            flag!(
                "data",
                "string",
                "Icon data directory (default: $AOIDE_ICON_DATA, else the `nix build .#iconify-data` result's share/iconify)."
            )
        ],
        gated: true,
        implemented: true,
        handler: handle_resolve,
    ));
}

// ─────────────────────────── data-dir + raw IconifyJSON access ───────────────────────────

fn data_dir(inv: &Invocation) -> Result<PathBuf, String> {
    if let Some(d) = inv.flags.get("data") {
        return Ok(PathBuf::from(d));
    }
    if let Ok(d) = std::env::var("AOIDE_ICON_DATA") {
        if !d.is_empty() {
            return Ok(PathBuf::from(d));
        }
    }
    Err("no icon data directory: pass `--data <dir>`, set $AOIDE_ICON_DATA, or run `nix build .#iconify-data` and point at `<result>/share/iconify`".to_string())
}

fn load_json(path: &Path) -> Result<Value, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{} is not valid JSON: {e}", path.display()))
}

/// A collection's `icons.json` (an `IconifyJSON` document,
/// `https://iconify.design/docs/types/iconify-json.html`) as a bare
/// [`Value`] — see the module doc for why no typed struct is used.
fn load_icon_set(data: &Path, collection: &str) -> Result<Value, String> {
    let set = load_json(&data.join(collection).join("icons.json"))?;
    if !set.is_object() {
        return Err(format!("{collection}/icons.json is not a JSON object"));
    }
    Ok(set)
}

/// A collection's `info.json` (`IconifyInfo`,
/// `https://iconify.design/docs/types/iconify-json-metadata.html`).
fn load_info(data: &Path, collection: &str) -> Result<Value, String> {
    load_json(&data.join(collection).join("info.json"))
}

/// Inverts `metadata.json`'s `category -> [name, …]` map into
/// `name -> [category, …]`, the shape `icon list`'s search/`categories`
/// field wants. Absent (ph ships `suffixes`, not `categories`) or
/// unparsable metadata is a silent empty map, never a hard error — a
/// collection missing this optional file is still fully listable/
/// resolvable by name.
fn load_categories(data: &Path, collection: &str) -> BTreeMap<String, Vec<String>> {
    let path = data.join(collection).join("metadata.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return BTreeMap::new(),
    };
    let meta: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return BTreeMap::new(),
    };
    let mut inverted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(categories) = meta.get("categories").and_then(Value::as_object) {
        for (category, names) in categories {
            if let Some(arr) = names.as_array() {
                for n in arr {
                    if let Some(n) = n.as_str() {
                        inverted
                            .entry(n.to_string())
                            .or_default()
                            .push(category.clone());
                    }
                }
            }
        }
    }
    inverted
}

// ─────────────────────────── alias-chain walk + property fold ───────────────────────────

fn icon_node<'a>(set: &'a Value, key: &str) -> Option<&'a Value> {
    set.get("icons").and_then(|o| o.get(key))
}

fn alias_node<'a>(set: &'a Value, key: &str) -> Option<&'a Value> {
    set.get("aliases").and_then(|o| o.get(key))
}

/// The icon-or-alias node for a chain entry — every entry in a chain
/// [`icon_chain`] returns is, by construction, one or the other.
fn chain_node<'a>(set: &'a Value, key: &str) -> &'a Value {
    icon_node(set, key)
        .or_else(|| alias_node(set, key))
        .expect("chain entries always resolve to a node")
}

/// The ordered chain from `name` to its real icon: `[name, …, base]`, where
/// `base` is the only entry present in `set.icons`. Ports the cycle-safe
/// walk `icon-set/tree.ts`'s `getIconsTree` performs (a `resolved` map
/// marking names in progress) as a plain loop with a `seen` set, since
/// [`resolve_icon_data`] only ever needs ONE name's chain at a time, never
/// the whole collection's tree up front.
fn icon_chain(set: &Value, collection: &str, name: &str) -> Result<Vec<String>, String> {
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = name.to_string();
    loop {
        if !seen.insert(cur.clone()) {
            return Err(format!("alias cycle in `{collection}` at `{cur}`"));
        }
        if icon_node(set, &cur).is_some() {
            chain.push(cur);
            return Ok(chain);
        }
        match alias_node(set, &cur) {
            Some(a) => {
                let parent = a
                    .get("parent")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("alias `{cur}` in `{collection}` has no `parent`"))?
                    .to_string();
                chain.push(cur.clone());
                cur = parent;
            }
            None => {
                return Err(format!(
                    "`{cur}` is neither an icon nor an alias in `{collection}`"
                ))
            }
        }
    }
}

fn resolve_base_name(set: &Value, collection: &str, name: &str) -> Option<String> {
    icon_chain(set, collection, name)
        .ok()
        .and_then(|c| c.last().cloned())
}

struct ResolvedIcon {
    body: String,
    left: f64,
    top: f64,
    width: f64,
    height: f64,
    rotate: i64,
    h_flip: bool,
    v_flip: bool,
}

/// `getIconData`/`internalGetIconData` (`icon-set/get-icon.ts:12-49`) —
/// see the module doc for why a single linear walk over [`icon_chain`]
/// reproduces the exact same fold as upstream's pairwise recursion.
fn resolve_icon_data(set: &Value, collection: &str, name: &str) -> Result<ResolvedIcon, String> {
    let chain = icon_chain(set, collection, name)?;
    let base_key = chain
        .last()
        .expect("icon_chain always returns a non-empty chain");
    let base = icon_node(set, base_key).expect("icon_chain's last entry is always a real icon");
    let body = base
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("icon `{base_key}` in `{collection}` has no `body`"))?
        .to_string();

    // Dimensions/body: closest-to-`name` wins, walking outward; the SET's
    // own root fields are the fallback, universal IconifyIcon defaults
    // (`icon/defaults.ts:23-28`: left/top 0, width/height 16) are the
    // fallback after that.
    let mut left = None;
    let mut top = None;
    let mut width = None;
    let mut height = None;
    for key in &chain {
        let node = chain_node(set, key);
        left = left.or_else(|| node.get("left").and_then(Value::as_f64));
        top = top.or_else(|| node.get("top").and_then(Value::as_f64));
        width = width.or_else(|| node.get("width").and_then(Value::as_f64));
        height = height.or_else(|| node.get("height").and_then(Value::as_f64));
    }
    let left = left
        .or_else(|| set.get("left").and_then(Value::as_f64))
        .unwrap_or(0.0);
    let top = top
        .or_else(|| set.get("top").and_then(Value::as_f64))
        .unwrap_or(0.0);
    let width = width
        .or_else(|| set.get("width").and_then(Value::as_f64))
        .unwrap_or(16.0);
    let height = height
        .or_else(|| set.get("height").and_then(Value::as_f64))
        .unwrap_or(16.0);

    // Transforms: hFlip/vFlip XOR and rotate SUM across the whole chain
    // plus the SET's own root (`icon/transformations.ts:11-19`).
    let mut h_flip = false;
    let mut v_flip = false;
    let mut rotate: i64 = 0;
    for key in &chain {
        let node = chain_node(set, key);
        h_flip ^= node.get("hFlip").and_then(Value::as_bool).unwrap_or(false);
        v_flip ^= node.get("vFlip").and_then(Value::as_bool).unwrap_or(false);
        rotate += node.get("rotate").and_then(Value::as_i64).unwrap_or(0);
    }
    h_flip ^= set.get("hFlip").and_then(Value::as_bool).unwrap_or(false);
    v_flip ^= set.get("vFlip").and_then(Value::as_bool).unwrap_or(false);
    rotate += set.get("rotate").and_then(Value::as_i64).unwrap_or(0);
    let rotate = rotate.rem_euclid(4);

    Ok(ResolvedIcon {
        body,
        left,
        top,
        width,
        height,
        rotate,
        h_flip,
        v_flip,
    })
}

// ─────────────────────────── SVG assembly (iconToSVG + iconToHTML port) ───────────────────────────

/// `Display`s a float the way JS's `Number.prototype.toString()` does for
/// the plain integers/halves this algorithm ever produces: no trailing
/// `.0` on a whole number.
fn fmt_num(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// Port of `svg/defs.ts`'s `splitSVGDefs` — pulls a `<defs>…</defs>` block
/// (iconoir's `podcast`/`podcast-solid`, which composite via
/// `<use href="#…">`, are the pinned-data example) out of `content` so
/// [`wrap_svg_content`] can re-attach it OUTSIDE any `<g transform>` wrap;
/// `<defs>` content is never rendered in place and must never itself be
/// transformed. Unlike upstream's `splitSVGDefs`, which tracks one open/
/// close index pair across the whole loop, this recomputes `idx`/`end` from
/// the shrunk `content` on every iteration — identical output for the
/// single-`<defs>`-block bodies either pinned collection ever produces, but
/// worth knowing before assuming the two are index-for-index the same port.
fn split_svg_defs(content: &str, tag: &str) -> (String, String) {
    let mut defs = String::new();
    let mut content = content.to_string();
    let open = format!("<{tag}");
    let close = format!("</{tag}");
    while let Some(idx) = content.find(open.as_str()) {
        let Some(start_rel) = content[idx..].find('>') else {
            break;
        };
        let start = idx + start_rel;
        let Some(end) = content.find(close.as_str()) else {
            break;
        };
        let Some(end_end_rel) = content[end..].find('>') else {
            break;
        };
        let end_end = end + end_end_rel;
        defs.push_str(content[start + 1..end].trim());
        let mut next = content[..idx].trim().to_string();
        next.push_str(&content[end_end + 1..]);
        content = next;
    }
    (defs, content)
}

fn wrap_svg_content(body: &str, start: &str, end: &str) -> String {
    let (defs, content) = split_svg_defs(body, "defs");
    if defs.is_empty() {
        format!("{start}{content}{end}")
    } else {
        format!("<defs>{defs}</defs>{start}{content}{end}")
    }
}

/// Port of `iconToSVG`'s transform-application pass (`svg/build.ts:67-176`),
/// restricted to the icon's OWN transform — see the module doc for why the
/// upstream second (caller-customisation) pass is always the identity here.
/// Returns the (possibly `<g transform>`-wrapped) body and the FINAL
/// `[left, top, width, height]` box — post odd-rotation swap, matching the
/// fetched source (see the module doc's note on the brief's own paraphrase).
fn transform_body(icon: &ResolvedIcon) -> (String, [f64; 4]) {
    let mut left = icon.left;
    let mut top = icon.top;
    let mut width = icon.width;
    let mut height = icon.height;
    let mut body = icon.body.clone();
    let mut transformations: Vec<String> = Vec::new();

    let mut rotation = icon.rotate;
    if icon.h_flip {
        if icon.v_flip {
            rotation += 2;
        } else {
            transformations.push(format!(
                "translate({} {})",
                fmt_num(width + left),
                fmt_num(0.0 - top)
            ));
            transformations.push("scale(-1 1)".to_string());
            top = 0.0;
            left = 0.0;
        }
    } else if icon.v_flip {
        transformations.push(format!(
            "translate({} {})",
            fmt_num(0.0 - left),
            fmt_num(height + top)
        ));
        transformations.push("scale(1 -1)".to_string());
        top = 0.0;
        left = 0.0;
    }

    let rotation = rotation.rem_euclid(4);
    match rotation {
        1 => {
            let t = height / 2.0 + top;
            transformations.insert(0, format!("rotate(90 {} {})", fmt_num(t), fmt_num(t)));
        }
        2 => {
            transformations.insert(
                0,
                format!(
                    "rotate(180 {} {})",
                    fmt_num(width / 2.0 + left),
                    fmt_num(height / 2.0 + top)
                ),
            );
        }
        3 => {
            let t = width / 2.0 + left;
            transformations.insert(0, format!("rotate(-90 {} {})", fmt_num(t), fmt_num(t)));
        }
        _ => {}
    }

    if rotation % 2 == 1 {
        if left != top {
            std::mem::swap(&mut left, &mut top);
        }
        if width != height {
            std::mem::swap(&mut width, &mut height);
        }
    }

    if !transformations.is_empty() {
        body = wrap_svg_content(
            &body,
            &format!("<g transform=\"{}\">", transformations.join(" ")),
            "</g>",
        );
    }

    (body, [left, top, width, height])
}

/// Port of `iconToHTML` (`svg/html.ts`) plus the tail of `iconToSVG` that
/// assembles the `viewBox` attribute string (`svg/build.ts:210-215`) — see
/// the module doc for the deliberate width/height simplification.
fn assemble_svg(body: &str, box_dims: [f64; 4], mono: bool) -> String {
    let [left, top, width, height] = box_dims;
    let mut svg = String::from("<svg xmlns=\"http://www.w3.org/2000/svg\"");
    if body.contains("xlink:") {
        svg.push_str(" xmlns:xlink=\"http://www.w3.org/1999/xlink\"");
    }
    svg.push_str(&format!(
        " width=\"{}\" height=\"{}\"",
        fmt_num(width),
        fmt_num(height)
    ));
    svg.push_str(&format!(
        " viewBox=\"{} {} {} {}\"",
        fmt_num(left),
        fmt_num(top),
        fmt_num(width),
        fmt_num(height)
    ));
    if mono {
        svg.push_str(" color=\"#000000\"");
    }
    svg.push('>');
    svg.push_str(body);
    svg.push_str("</svg>");
    svg
}

// ─────────────────────────── mono vs multicolor ───────────────────────────

/// Textual scan (no XML crate, `design/p-icon-brief.md` §C6) for every
/// `fill=`/`stroke=`/`stop-color=` attribute VALUE, PLUS the same three
/// properties declared inside a `style="…"` attribute or a `<style>…
/// </style>` block (a custom asset is free to carry either — the bare-
/// attribute scan alone missed both, review fixup): `currentColor`, `none`,
/// `inherit`, `transparent`, and a `url(#…)` reference are transparent to
/// tinting; anything else (a hex/`rgb()`/named literal) makes the icon
/// multicolor. An unrelated attribute that happens to end in one of these
/// names (e.g. `flood-fill=`) still carries a colour-shaped value, so a
/// substring match classifies it the same way a strict parse would.
fn detect_mono(body: &str) -> bool {
    if body.contains("<image") {
        return false;
    }
    for attr in ["fill", "stroke", "stop-color"] {
        for value in attr_values(body, attr) {
            let v = value.trim();
            if v.is_empty()
                || v.eq_ignore_ascii_case("none")
                || v.eq_ignore_ascii_case("currentcolor")
                || v.starts_with("url(")
            {
                continue;
            }
            return false;
        }
    }
    for style in attr_values(body, "style") {
        if has_literal_color_declaration(style) {
            return false;
        }
    }
    for style in extract_style_tags(body) {
        if has_literal_color_declaration(style) {
            return false;
        }
    }
    true
}

/// Whether a `style="…"` attribute value or a `<style>` block's text
/// declares `fill`/`stroke`/`stop-color` with a literal colour — same
/// allow-list as [`detect_mono`]'s bare-attribute scan (`none`/
/// `currentColor`/`inherit`/`transparent`/a `url(#…)` reference), so a
/// duotone's `opacity` tweak or a `stroke:none` stays mono but
/// `fill:#ff0000` does not.
fn has_literal_color_declaration(css: &str) -> bool {
    for prop in ["fill:", "stroke:", "stop-color:"] {
        let mut start = 0usize;
        while let Some(rel) = css.get(start..).and_then(|s| s.find(prop)) {
            let value_start = start + rel + prop.len();
            let rest = &css[value_start..];
            let end = rest.find([';', '}']).unwrap_or(rest.len());
            let value = rest[..end].trim();
            start = value_start + end;
            let transparent = value.is_empty()
                || value.eq_ignore_ascii_case("none")
                || value.eq_ignore_ascii_case("currentcolor")
                || value.eq_ignore_ascii_case("inherit")
                || value.eq_ignore_ascii_case("transparent")
                || value.starts_with("url(");
            if !transparent {
                return true;
            }
        }
    }
    false
}

/// Every `<style>…</style>` block's inner text, in order — a `<style>`
/// element is the same colour-literal risk `style="…"` carries, just at
/// element scope instead of attribute scope.
fn extract_style_tags(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while let Some(rel) = body.get(start..).and_then(|s| s.find("<style")) {
        let open = start + rel;
        let Some(tag_end_rel) = body[open..].find('>') else {
            break;
        };
        let content_start = open + tag_end_rel + 1;
        let Some(close_rel) = body[content_start..].find("</style") else {
            break;
        };
        let content_end = content_start + close_rel;
        out.push(&body[content_start..content_end]);
        start = content_end;
    }
    out
}

/// Every value of `attr="…"`/`attr='…'` in `body`, in order.
fn attr_values<'a>(body: &'a str, attr: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for quote in ['"', '\''] {
        let needle = format!("{attr}={quote}");
        let mut start = 0usize;
        while let Some(pos) = body.get(start..).and_then(|s| s.find(needle.as_str())) {
            let vstart = start + pos + needle.len();
            match body.get(vstart..).and_then(|s| s.find(quote)) {
                Some(end_rel) => {
                    out.push(&body[vstart..vstart + end_rel]);
                    start = vstart + end_rel + 1;
                }
                None => break,
            }
        }
    }
    out
}

/// Injects `color="#000000"` into a custom SVG's root `<svg …>` tag when it
/// doesn't already carry a `color=` attribute — the same determinism
/// [`assemble_svg`] bakes into every Iconify-sourced mono icon, applied to a
/// verbatim custom asset instead of a freshly-assembled one.
fn ensure_root_color(svg: &str) -> String {
    let Some(tag_start) = svg.find("<svg") else {
        return svg.to_string();
    };
    let Some(tag_end_rel) = svg[tag_start..].find('>') else {
        return svg.to_string();
    };
    let tag_end = tag_start + tag_end_rel;
    if svg[tag_start..tag_end].contains("color=") {
        return svg.to_string();
    }
    let mut out = String::with_capacity(svg.len() + 20);
    out.push_str(&svg[..tag_end]);
    out.push_str(" color=\"#000000\"");
    out.push_str(&svg[tag_end..]);
    out
}

/// Best-effort intrinsic size for a custom SVG: the root tag's own
/// `width`/`height` attributes, else its `viewBox`'s 3rd/4th numbers, else
/// `None` (catalog `width`/`height` are omitted, never guessed).
fn sniff_svg_dims(svg: &str) -> (Option<f64>, Option<f64>) {
    let Some(tag_start) = svg.find("<svg") else {
        return (None, None);
    };
    let Some(tag_end_rel) = svg[tag_start..].find('>') else {
        return (None, None);
    };
    let tag = &svg[tag_start..tag_start + tag_end_rel];
    let w = attr_values(tag, "width")
        .first()
        .and_then(|v| v.trim_end_matches("px").trim().parse::<f64>().ok());
    let h = attr_values(tag, "height")
        .first()
        .and_then(|v| v.trim_end_matches("px").trim().parse::<f64>().ok());
    if let (Some(w), Some(h)) = (w, h) {
        return (Some(w), Some(h));
    }
    if let Some(vb) = attr_values(tag, "viewBox").first() {
        let parts: Vec<f64> = vb
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .collect();
        if parts.len() == 4 {
            return (Some(parts[2]), Some(parts[3]));
        }
    }
    (None, None)
}

// ─────────────────────────── catalog.json / selection.json ───────────────────────────

/// Builds one `catalog.json` icon entry (§C1's shape). `license` is ALWAYS
/// present (`null` for a custom asset, never omitted); `collection`/`name`/
/// `version`/`width`/`height` are omitted entirely when `None` — the
/// selection manifest is this same shape with every one of THOSE optional
/// keys absent too, which is what makes it "the same object minus the
/// generated keys".
#[allow(clippy::too_many_arguments)]
fn catalog_entry(
    file: String,
    mono: bool,
    collection: Option<String>,
    name: Option<String>,
    source: &str,
    license: Option<Value>,
    version: Option<String>,
    width: Option<f64>,
    height: Option<f64>,
) -> Value {
    let mut m = Map::new();
    m.insert("file".to_string(), json!(file));
    m.insert("mono".to_string(), json!(mono));
    if let Some(c) = collection {
        m.insert("collection".to_string(), json!(c));
    }
    if let Some(n) = name {
        m.insert("name".to_string(), json!(n));
    }
    m.insert("source".to_string(), json!(source));
    m.insert("license".to_string(), license.unwrap_or(Value::Null));
    if let Some(v) = version {
        m.insert("version".to_string(), json!(v));
    }
    if let Some(w) = width {
        m.insert("width".to_string(), json_num(w));
    }
    if let Some(h) = height {
        m.insert("height".to_string(), json_num(h));
    }
    Value::Object(m)
}

/// Every pinned-data dimension is a whole number (§B: `width`/`height`
/// default 16, both pinned collections' roots are 24/256) — emit `24`, not
/// `24.0`, matching `design/p-icon-brief.md` §C1's own `catalog.json`
/// example byte for byte; a genuinely fractional custom-asset dimension (an
/// odd `viewBox`) still round-trips as a JSON float.
fn json_num(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        json!(v as i64)
    } else {
        json!(v)
    }
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "asset".to_string()
    } else {
        out
    }
}

enum Selector {
    Iconify { collection: String, name: String },
    Custom { path: PathBuf },
}

/// A custom asset is `file:<path>` or a bare path containing `/`; anything
/// else must be `<collection>:<name>` (§C1) — never guessed either way.
///
/// SECURITY (review fixup): `collection`/`name` become path COMPONENTS —
/// `run_resolve` joins them as `<out>/<collection>/<name>.svg` — so each is
/// validated by [`validate_plain_name`] BEFORE ever reaching a path join.
/// Without this, an id like `"..:pwned"` has no `/` (so it skips the
/// Custom-path branch above) and no `file:` prefix, reaches this arm as
/// `collection = ".."`, and `<out>/../pwned.svg` writes into `--out`'s
/// PARENT directory — a live-verified traversal (both on write and, via a
/// tampered `catalog.json`'s `file` value, on the later prune's
/// `remove_file`). `run_resolve` also re-checks the ASSEMBLED path against
/// `--out` right before every write/remove (defense in depth) — this is
/// the primary gate, catching the exploit before any path is even built.
fn parse_selector(id: &str) -> Result<Selector, String> {
    if let Some(rest) = id.strip_prefix("file:") {
        return Ok(Selector::Custom {
            path: PathBuf::from(rest),
        });
    }
    if id.contains('/') {
        return Ok(Selector::Custom {
            path: PathBuf::from(id),
        });
    }
    match id.split_once(':') {
        Some((collection, name)) if !collection.is_empty() && !name.is_empty() => {
            if !validate_plain_name(collection) || !validate_plain_name(name) {
                return Err(format!(
                    "icon: identifier \"{id}\": collection and name must be plain names (letters, digits, - _ .), no path components"
                ));
            }
            Ok(Selector::Iconify { collection: collection.to_string(), name: name.to_string() })
        }
        _ => Err(format!(
            "`{id}` is not a valid icon identifier: expected `<collection>:<name>`, `file:<path>`, or a path containing `/`"
        )),
    }
}

/// A `<collection>` or `<name>` component is safe to join into a path only
/// if it can never resolve to anything but a single, ordinary path
/// segment: no `..` substring, no `/` or `\`, not the bare `.` component,
/// and — after those checks — every character in `[A-Za-z0-9_.-]`. Every
/// real Iconify prefix/icon name (both pinned collections, verified) is
/// already kebab-case ASCII, so this rejects nothing legitimate.
fn validate_plain_name(value: &str) -> bool {
    if value.is_empty()
        || value == "."
        || value.contains("..")
        || value.contains('/')
        || value.contains('\\')
    {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

enum ResolveError {
    Usage(String),
    Error(String),
}

struct ResolveOutcome {
    written: Vec<String>,
    unchanged: Vec<String>,
    removed: Vec<String>,
    /// A catalog `file` entry that pointed outside `--out` (a tampered or
    /// pre-fix legacy `catalog.json`, never anything this code itself would
    /// produce today — see [`path_is_within`]) — reported so a caller can
    /// see it was refused rather than silently dropped, but the file
    /// itself is left exactly where it was: never deleted.
    skipped: Vec<String>,
    catalog: Value,
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> std::io::Result<bool> {
    if let Ok(existing) = std::fs::read(path) {
        if existing == bytes {
            return Ok(false);
        }
    }
    aoide_storage::fs::atomic_write_bytes(path, bytes)?;
    Ok(true)
}

/// Runs [`write_if_changed`] and records the outcome into `written`/
/// `unchanged` — the ONE place every write site (an Iconify SVG, a custom
/// asset copy, `catalog.json` itself) does its write-then-classify
/// bookkeeping, rather than three copies of the same three-armed match
/// (review fixup).
fn record_write(
    target: &Path,
    bytes: &[u8],
    rel: &str,
    written: &mut Vec<String>,
    unchanged: &mut Vec<String>,
) -> Result<(), ResolveError> {
    match write_if_changed(target, bytes) {
        Ok(true) => written.push(rel.to_string()),
        Ok(false) => unchanged.push(rel.to_string()),
        Err(e) => {
            return Err(ResolveError::Error(format!(
                "writing {}: {e}",
                target.display()
            )))
        }
    }
    Ok(())
}

/// Defense in depth (review fixup) against [`parse_selector`]'s own
/// `validate_plain_name` gate: creates `target`'s parent directory, then
/// canonicalizes it and refuses to proceed unless it lands inside
/// `out_canon`. For every path this module builds today (a validated
/// `<collection>/<name>.svg`, a `slugify`d `custom/<slug>.<ext>`, or
/// `catalog.json` itself, all joined under `out`) this can never actually
/// fire — it exists so a FUTURE path-building change can't reintroduce the
/// traversal `validate_plain_name` closes today without also passing this
/// second, independent check.
fn ensure_write_target_within(
    out_canon: &Path,
    target: &Path,
    id: &str,
) -> Result<(), ResolveError> {
    let parent = target.parent().ok_or_else(|| {
        ResolveError::Error(format!("`{id}`: target path has no parent directory"))
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|e| ResolveError::Error(format!("creating {}: {e}", parent.display())))?;
    let parent_canon = parent
        .canonicalize()
        .map_err(|e| ResolveError::Error(format!("resolving {}: {e}", parent.display())))?;
    if !parent_canon.starts_with(out_canon) {
        return Err(ResolveError::Usage(format!(
            "icon: identifier \"{id}\": resolved path {} escapes --out; refusing to write",
            parent.display()
        )));
    }
    Ok(())
}

/// Whether an EXISTING path canonicalizes to somewhere inside `out_canon` —
/// the same defense-in-depth posture as [`ensure_write_target_within`],
/// applied before `run_resolve`'s prune step ever calls `remove_file` on a
/// path a catalog's `file` value named (untrusted: it could be a tampered
/// or pre-fix legacy `catalog.json`, not just this run's own output).
fn path_is_within(out_canon: &Path, target: &Path) -> bool {
    match target.canonicalize() {
        Ok(canon) => canon.starts_with(out_canon),
        Err(_) => false,
    }
}

/// The one writer (§C1). `ids` need not be pre-sorted or de-duplicated —
/// this sorts and dedups them itself so slug assignment for custom assets
/// (and catalog/file layout generally) is a pure function of the SELECTION
/// SET, never of positional-arg order, which is what makes a repeat resolve
/// with the same selection a true byte no-op regardless of how the caller
/// spelled it.
fn run_resolve(ids: &[String], out: &Path, data: &Path) -> Result<ResolveOutcome, ResolveError> {
    let mut sorted: Vec<String> = ids.to_vec();
    sorted.sort();
    sorted.dedup();

    std::fs::create_dir_all(out)
        .map_err(|e| ResolveError::Error(format!("creating {}: {e}", out.display())))?;
    let out_canon = out
        .canonicalize()
        .map_err(|e| ResolveError::Error(format!("resolving {}: {e}", out.display())))?;

    let mut sets: BTreeMap<String, Value> = BTreeMap::new();
    let mut infos: BTreeMap<String, Value> = BTreeMap::new();
    let mut new_catalog: Map<String, Value> = Map::new();
    let mut new_files: BTreeSet<String> = BTreeSet::new();
    let mut used_slugs: HashSet<String> = HashSet::new();
    let mut written = Vec::new();
    let mut unchanged = Vec::new();

    for id in &sorted {
        let selector = parse_selector(id).map_err(ResolveError::Usage)?;
        match selector {
            Selector::Iconify { collection, name } => {
                if !sets.contains_key(&collection) {
                    sets.insert(
                        collection.clone(),
                        load_icon_set(data, &collection).map_err(ResolveError::Error)?,
                    );
                }
                if !infos.contains_key(&collection) {
                    infos.insert(
                        collection.clone(),
                        load_info(data, &collection).map_err(ResolveError::Error)?,
                    );
                }
                let set = &sets[&collection];
                let resolved = resolve_icon_data(set, &collection, &name)
                    .map_err(|e| ResolveError::Usage(format!("`{id}`: {e}")))?;
                let mono = detect_mono(&resolved.body);
                let (body, box_dims) = transform_body(&resolved);
                let svg = assemble_svg(&body, box_dims, mono);

                let info = &infos[&collection];
                let license_name = info
                    .get("license")
                    .and_then(|l| l.get("title"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let license_spdx = info
                    .get("license")
                    .and_then(|l| l.get("spdx"))
                    .and_then(Value::as_str);
                let license_url = info
                    .get("license")
                    .and_then(|l| l.get("url"))
                    .and_then(Value::as_str);
                let version = info
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let license =
                    json!({"name": license_name, "spdx": license_spdx, "url": license_url});

                let rel = format!("{collection}/{name}.svg");
                let target = out.join(&rel);
                ensure_write_target_within(&out_canon, &target, id)?;
                record_write(&target, svg.as_bytes(), &rel, &mut written, &mut unchanged)?;
                new_files.insert(rel.clone());
                new_catalog.insert(
                    id.clone(),
                    catalog_entry(
                        rel,
                        mono,
                        Some(collection.clone()),
                        Some(name.clone()),
                        "iconify",
                        Some(license),
                        version,
                        Some(resolved.width),
                        Some(resolved.height),
                    ),
                );
            }
            Selector::Custom { path } => {
                let resolved_path = if path.is_absolute() {
                    path.clone()
                } else {
                    std::env::current_dir()
                        .map_err(|e| ResolveError::Error(e.to_string()))?
                        .join(&path)
                };
                let ext = match resolved_path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()) {
                    Some(e) if e == "svg" => "svg",
                    Some(e) if e == "png" => "png",
                    _ => {
                        return Err(ResolveError::Usage(format!(
                            "`{id}`: only `.svg`/`.png` custom assets are supported (pack independence, not a promise to render arbitrary formats)"
                        )))
                    }
                };
                let raw = std::fs::read(&resolved_path).map_err(|e| {
                    ResolveError::Error(format!("reading {}: {e}", resolved_path.display()))
                })?;

                let base_slug = slugify(
                    resolved_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("asset"),
                );
                let mut slug = base_slug.clone();
                let mut n = 2;
                while !used_slugs.insert(slug.clone()) {
                    slug = format!("{base_slug}-{n}");
                    n += 1;
                }

                let (mono, bytes) = if ext == "svg" {
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    let m = detect_mono(&text);
                    let out_text = if m { ensure_root_color(&text) } else { text };
                    (m, out_text.into_bytes())
                } else {
                    (false, raw)
                };
                let (width, height) = if ext == "svg" {
                    sniff_svg_dims(&String::from_utf8_lossy(&bytes))
                } else {
                    (None, None)
                };

                let rel = format!("custom/{slug}.{ext}");
                let target = out.join(&rel);
                ensure_write_target_within(&out_canon, &target, id)?;
                record_write(&target, &bytes, &rel, &mut written, &mut unchanged)?;
                new_files.insert(rel.clone());
                new_catalog.insert(
                    id.clone(),
                    catalog_entry(rel, mono, None, None, "custom", None, None, width, height),
                );
            }
        }
    }

    // Prune: any file the OLD catalog named that the current selection no
    // longer does gets removed (house rule 7 — nothing outlives its own
    // selection entry). `path_is_within` is checked before every
    // `remove_file` (review fixup): a `file` value that resolves outside
    // `--out` (a tampered or pre-fix legacy `catalog.json` — never
    // anything this code produces today) is reported as skipped, and the
    // path it names is left untouched, never deleted.
    let mut removed = Vec::new();
    let mut skipped = Vec::new();
    let catalog_path = out.join("catalog.json");
    if let Ok(text) = std::fs::read_to_string(&catalog_path) {
        if let Ok(old) = serde_json::from_str::<Value>(&text) {
            if let Some(old_icons) = old.get("icons").and_then(Value::as_object) {
                for entry in old_icons.values() {
                    if let Some(file) = entry.get("file").and_then(Value::as_str) {
                        if !new_files.contains(file) {
                            let p = out.join(file);
                            if p.is_file() {
                                if path_is_within(&out_canon, &p) {
                                    std::fs::remove_file(&p).map_err(|e| {
                                        ResolveError::Error(format!(
                                            "removing {}: {e}",
                                            p.display()
                                        ))
                                    })?;
                                    removed.push(file.to_string());
                                } else {
                                    skipped.push(file.to_string());
                                }
                            } else {
                                removed.push(file.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    removed.sort();
    removed.dedup();
    skipped.sort();
    skipped.dedup();

    let catalog = json!({"schemaVersion": 0, "icons": Value::Object(new_catalog)});
    let mut catalog_bytes =
        serde_json::to_vec_pretty(&catalog).map_err(|e| ResolveError::Error(e.to_string()))?;
    catalog_bytes.push(b'\n');
    ensure_write_target_within(&out_canon, &catalog_path, "catalog.json")?;
    record_write(
        &catalog_path,
        &catalog_bytes,
        "catalog.json",
        &mut written,
        &mut unchanged,
    )?;

    written.sort();
    unchanged.sort();

    Ok(ResolveOutcome {
        written,
        unchanged,
        removed,
        skipped,
        catalog,
    })
}

// ─────────────────────────── handlers ───────────────────────────

fn handle_collections(inv: &Invocation) -> Outcome {
    let cmd = "icon.collections";
    let data = match data_dir(inv) {
        Ok(d) => d,
        Err(e) => return Outcome::error(cmd, e),
    };
    let read_dir = match std::fs::read_dir(&data) {
        Ok(rd) => rd,
        Err(e) => return Outcome::error(cmd, format!("reading {}: {e}", data.display())),
    };
    let mut dirs: Vec<PathBuf> = read_dir
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();

    let mut entries = Vec::new();
    for dir in dirs {
        let info_path = dir.join("info.json");
        if !info_path.is_file() {
            continue;
        }
        let info = match load_json(&info_path) {
            Ok(i) => i,
            Err(_) => continue,
        };
        entries.push(json!({
            "prefix": info.get("prefix").cloned().unwrap_or(Value::Null),
            "name": info.get("name").cloned().unwrap_or(Value::Null),
            "version": info.get("version").cloned().unwrap_or(Value::Null),
            "total": info.get("total").cloned().unwrap_or(Value::Null),
            "license": info.get("license").cloned().unwrap_or(Value::Null),
            "author": info.get("author").cloned().unwrap_or(Value::Null),
            "path": dir.to_string_lossy(),
        }));
    }

    Outcome::ok(
        cmd,
        format!(
            "{} icon collection(s) under {}",
            entries.len(),
            data.display()
        ),
    )
    .with_data(json!(entries))
}

fn icon_matches(needle: Option<&str>, name: &str, categories: &[String]) -> bool {
    match needle {
        None => true,
        Some(n) => {
            name.to_lowercase().contains(n)
                || categories.iter().any(|c| c.to_lowercase().contains(n))
        }
    }
}

fn handle_list(inv: &Invocation) -> Outcome {
    let cmd = "icon.list";
    let collection = match inv.flags.get("collection") {
        Some(c) => c.clone(),
        None => return Outcome::usage(cmd, "`--collection <prefix>` is required"),
    };
    let data = match data_dir(inv) {
        Ok(d) => d,
        Err(e) => return Outcome::error(cmd, e),
    };
    let set = match load_icon_set(&data, &collection) {
        Ok(s) => s,
        Err(e) => return Outcome::error(cmd, e),
    };
    let categories = load_categories(&data, &collection);

    let empty = Map::new();
    let icons_obj = set
        .get("icons")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let aliases_obj = set
        .get("aliases")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    // name, alias-parent (if any), categories.
    let mut entries: Vec<(String, Option<String>, Vec<String>)> = Vec::new();
    for name in icons_obj.keys() {
        entries.push((
            name.clone(),
            None,
            categories.get(name).cloned().unwrap_or_default(),
        ));
    }
    for (name, alias) in aliases_obj {
        let parent = alias
            .get("parent")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let cats = categories.get(name).cloned().unwrap_or_else(|| {
            resolve_base_name(&set, &collection, name)
                .and_then(|b| categories.get(&b).cloned())
                .unwrap_or_default()
        });
        entries.push((name.clone(), Some(parent), cats));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let total = entries.len();

    let needle = inv.flags.get("search").map(|s| s.to_lowercase());
    let limit = match inv.flags.get("limit") {
        Some(v) => match v.parse::<usize>() {
            Ok(n) => Some(n),
            Err(_) => {
                return Outcome::usage(cmd, format!("`--limit {v}` is not a non-negative integer"))
            }
        },
        None => None,
    };

    let filtered: Vec<&(String, Option<String>, Vec<String>)> = entries
        .iter()
        .filter(|(name, _, cats)| icon_matches(needle.as_deref(), name, cats))
        .collect();
    let matched = filtered.len();
    let limited = match limit {
        Some(l) => &filtered[..filtered.len().min(l)],
        None => &filtered[..],
    };

    let icons_json: Vec<Value> = limited
        .iter()
        .map(|(name, alias, cats)| {
            let mut obj = Map::new();
            obj.insert("name".to_string(), json!(name));
            if let Some(p) = alias {
                obj.insert("alias".to_string(), json!(p));
            }
            obj.insert("categories".to_string(), json!(cats));
            Value::Object(obj)
        })
        .collect();

    Outcome::ok(cmd, format!("{matched} of {total} icon(s) in `{collection}`"))
        .with_data(json!({ "collection": collection, "total": total, "matched": matched, "icons": icons_json }))
}

fn handle_resolve(inv: &Invocation) -> Outcome {
    let cmd = "icon.resolve";
    let out = match inv.flags.get("out") {
        Some(o) => PathBuf::from(o),
        None => return Outcome::usage(cmd, "`--out <dir>` is required"),
    };

    let selection_flag = inv.flags.get("selection");
    if selection_flag.is_some() && !inv.args.is_empty() {
        return Outcome::usage(
            cmd,
            "pass either `<collection:name>` identifiers or `--selection <file>`, not both",
        );
    }

    let ids: Vec<String> = if let Some(sel_path) = selection_flag {
        let text = match std::fs::read_to_string(sel_path) {
            Ok(t) => t,
            Err(e) => return Outcome::error(cmd, format!("reading {sel_path}: {e}")),
        };
        let doc: Value = match serde_json::from_str(&text) {
            Ok(d) => d,
            Err(e) => {
                return Outcome::usage(
                    cmd,
                    format!("{sel_path} is not a valid selection manifest: {e}"),
                )
            }
        };
        doc.get("icons")
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    } else if !inv.args.is_empty() {
        inv.args.clone()
    } else {
        return Outcome::usage(cmd, "nothing to resolve: pass one or more `<collection:name>` identifiers or `--selection <file>`");
    };

    let data = match data_dir(inv) {
        Ok(d) => d,
        Err(e) => return Outcome::error(cmd, e),
    };

    match run_resolve(&ids, &out, &data) {
        Ok(res) => {
            let changed = res.written.clone();
            let skipped_note = if res.skipped.is_empty() {
                String::new()
            } else {
                format!(", {} skipped (outside --out, refused)", res.skipped.len())
            };
            Outcome::ok(
                cmd,
                format!(
                    "resolved {} identifier(s) into {} ({} written, {} unchanged, {} pruned{skipped_note})",
                    ids.len(),
                    out.display(),
                    res.written.len(),
                    res.unchanged.len(),
                    res.removed.len()
                ),
            )
            .gated(true)
            .changed(changed)
            .with_data(json!({
                "out": out.to_string_lossy(),
                "written": res.written,
                "unchanged": res.unchanged,
                "removed": res.removed,
                "skipped": res.skipped,
                "catalog": res.catalog,
            }))
        }
        Err(ResolveError::Usage(m)) => Outcome::usage(cmd, m),
        Err(ResolveError::Error(m)) => Outcome::error(cmd, m),
    }
}

// ─────────────────────────── tests ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// §D1's required fixture: a hand-authored `IconifyJSON` with an alias
    /// carrying BOTH `hFlip` and `rotate` over a parent that itself has its
    /// own `rotate`, plus a `left`/`top` override on that same alias, a
    /// SECOND alias whose `hFlip` cancels its parent's own `hFlip`
    /// (transform-merge "none" case), and a root-defaults-only icon.
    /// Neither pinned collection has an aliased transform (§B's "Shape
    /// facts"), so this fixture is the only way any of this is exercised.
    const FIXTURE: &str = r#"{
        "prefix": "test",
        "width": 20,
        "height": 20,
        "icons": {
            "base": { "body": "<path d=\"M0 0\"/>", "rotate": 2 },
            "plain": { "body": "<path d=\"M1 1\"/>" },
            "flipped": { "body": "<path d=\"M2 2\"/>", "hFlip": true }
        },
        "aliases": {
            "aliased": { "parent": "base", "hFlip": true, "rotate": 1, "left": 2, "top": 3 },
            "doubleflip": { "parent": "flipped", "hFlip": true }
        }
    }"#;

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).expect("fixture parses as JSON")
    }

    #[test]
    fn alias_merges_transforms_over_its_parents_own_transform() {
        let set = fixture();
        let resolved = resolve_icon_data(&set, "test", "aliased").unwrap();
        // rotate MERGES (sums): alias's own 1 + base's own 2 = 3.
        assert_eq!(resolved.rotate, 3, "rotate 1 + 2 must merge to 3");
        assert!(
            resolved.h_flip,
            "the alias's own hFlip must survive (base sets none)"
        );
        assert!(!resolved.v_flip);
        // dimensions: the alias's own left/top OVERRIDE the parent (which has
        // none); width/height fall all the way to the SET's own root (20x20,
        // since neither the alias nor `base` sets either).
        assert_eq!(
            (resolved.left, resolved.top, resolved.width, resolved.height),
            (2.0, 3.0, 20.0, 20.0)
        );
        assert_eq!(
            resolved.body, "<path d=\"M0 0\"/>",
            "body always comes from the real icon, never an alias"
        );
    }

    #[test]
    fn hflip_plus_hflip_merges_to_none() {
        let set = fixture();
        let resolved = resolve_icon_data(&set, "test", "doubleflip").unwrap();
        assert!(!resolved.h_flip, "hFlip + hFlip must cancel, not double");
        assert!(!resolved.v_flip);
        assert_eq!(resolved.rotate, 0);
    }

    #[test]
    fn root_defaults_only_icon_resolves_from_the_set_root() {
        let set = fixture();
        let resolved = resolve_icon_data(&set, "test", "plain").unwrap();
        assert_eq!(
            (resolved.left, resolved.top, resolved.width, resolved.height),
            (0.0, 0.0, 20.0, 20.0)
        );
        assert_eq!(resolved.rotate, 0);
        assert!(!resolved.h_flip && !resolved.v_flip);
    }

    #[test]
    fn unknown_identifier_is_an_error_not_a_guess() {
        let set = fixture();
        assert!(resolve_icon_data(&set, "test", "nope").is_err());
    }

    /// §D1: the emitted `viewBox` and `<g transform="…">` string for the
    /// alias+hFlip+rotate fixture, computed BY HAND against §B step 2 (and
    /// cross-checked directly against the fetched `svg/build.ts`, see the
    /// module doc): box starts `{left:2, top:3, width:20, height:20}`;
    /// hFlip (no vFlip) pushes `translate(22 -3)` + `scale(-1 1)` and zeros
    /// left/top; rotate=3 (270°) then unshifts `rotate(-90 10 10)`
    /// (`width/2+left` = `20/2+0`); the odd-rotation swap is a no-op here
    /// since width==height==20 either way.
    #[test]
    fn aliased_fixture_matches_the_hand_derived_svg_byte_for_byte() {
        let set = fixture();
        let resolved = resolve_icon_data(&set, "test", "aliased").unwrap();
        let mono = detect_mono(&resolved.body);
        assert!(mono, "a body with no colour token at all is mono");
        let (body, box_dims) = transform_body(&resolved);
        assert_eq!(
            box_dims,
            [0.0, 0.0, 20.0, 20.0],
            "viewBox box after the hFlip zeroing + no-op odd-rotation swap"
        );
        assert_eq!(body, "<g transform=\"rotate(-90 10 10) translate(22 -3) scale(-1 1)\"><path d=\"M0 0\"/></g>");
        let svg = assemble_svg(&body, box_dims, mono);
        assert_eq!(
            svg,
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\" color=\"#000000\">\
<g transform=\"rotate(-90 10 10) translate(22 -3) scale(-1 1)\"><path d=\"M0 0\"/></g></svg>"
        );
    }

    #[test]
    fn plain_icon_has_no_transform_wrap() {
        let set = fixture();
        let resolved = resolve_icon_data(&set, "test", "plain").unwrap();
        let mono = detect_mono(&resolved.body);
        let (body, box_dims) = transform_body(&resolved);
        assert_eq!(
            body, "<path d=\"M1 1\"/>",
            "no hFlip/vFlip/rotate -> no <g> wrap at all"
        );
        let svg = assemble_svg(&body, box_dims, mono);
        assert_eq!(
            svg,
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"20\" height=\"20\" viewBox=\"0 0 20 20\" color=\"#000000\"><path d=\"M1 1\"/></svg>"
        );
    }

    #[test]
    fn defs_stay_outside_the_transform_wrap() {
        let body = "<defs><path id=\"x\"/></defs><use href=\"#x\"/>";
        let wrapped = wrap_svg_content(body, "<g transform=\"rotate(90 1 1)\">", "</g>");
        assert_eq!(
            wrapped,
            "<defs><path id=\"x\"/></defs><g transform=\"rotate(90 1 1)\"><use href=\"#x\"/></g>"
        );
    }

    #[test]
    fn mono_detection_matches_the_pinned_data_examples() {
        // iconoir `undo`/`podcast`-shaped bodies: currentColor/none only.
        assert!(detect_mono(
            r#"<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 1"/></g>"#
        ));
        // iconoir `dots-grid-3x3-solid`/`snapchat`: a literal #fff makes it multicolor.
        assert!(!detect_mono(
            r##"<path fill="currentColor"/><path fill="#fff"/>"##
        ));
        // a gradient reference is transparent to tinting.
        assert!(detect_mono(r#"<path fill="url(#grad)" stroke="none"/>"#));
        // an embedded raster is always multicolor.
        assert!(!detect_mono(
            r#"<image href="data:image/png;base64,AAAA"/>"#
        ));
    }

    #[test]
    fn parse_selector_recognizes_all_three_forms() {
        assert!(matches!(
            parse_selector("iconoir:undo"),
            Ok(Selector::Iconify { .. })
        ));
        assert!(matches!(
            parse_selector("file:/abs/logo.svg"),
            Ok(Selector::Custom { .. })
        ));
        assert!(matches!(
            parse_selector("./assets/logo.png"),
            Ok(Selector::Custom { .. })
        ));
        assert!(parse_selector("not-an-identifier").is_err());
    }

    #[test]
    fn slugify_sanitizes_and_never_empties() {
        assert_eq!(slugify("My Logo (v2)!"), "my-logo-v2");
        assert_eq!(slugify("___"), "asset");
        assert_eq!(slugify("undo"), "undo");
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aoide_lyra_icon_test_{name}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_pinned_fixture(data: &Path, prefix: &str) {
        let dir = data.join(prefix);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("icons.json"), FIXTURE).unwrap();
        std::fs::write(
            dir.join("info.json"),
            format!(
                r#"{{"prefix":"{prefix}","name":"Test","total":3,"version":"1.0.0","author":{{"name":"Test"}},"license":{{"title":"MIT","spdx":"MIT","url":"https://example.invalid/license"}}}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn resolve_is_a_byte_no_op_on_repeat_and_reports_written_then_unchanged() {
        let data = scratch_dir("data-noop");
        write_pinned_fixture(&data, "test");
        let out = scratch_dir("out-noop");

        let ids = vec!["test:plain".to_string(), "test:aliased".to_string()];
        let first = run_resolve(&ids, &out, &data)
            .ok()
            .expect("first resolve succeeds");
        assert_eq!(first.written.len(), 3, "2 svgs + catalog.json"); // plain.svg, aliased.svg, catalog.json
        assert!(first.unchanged.is_empty());

        let before = std::fs::read(out.join("catalog.json")).unwrap();
        let second = run_resolve(&ids, &out, &data)
            .ok()
            .expect("second resolve succeeds");
        assert!(
            second.written.is_empty(),
            "a repeat resolve with nothing new must write nothing: {:?}",
            second.written
        );
        assert_eq!(second.unchanged.len(), 3);
        let after = std::fs::read(out.join("catalog.json")).unwrap();
        assert_eq!(
            before, after,
            "catalog.json is byte-identical across the no-op repeat"
        );

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn resolve_prunes_a_dropped_selection() {
        let data = scratch_dir("data-prune");
        write_pinned_fixture(&data, "test");
        let out = scratch_dir("out-prune");

        let both = vec!["test:plain".to_string(), "test:aliased".to_string()];
        run_resolve(&both, &out, &data).ok().unwrap();
        assert!(out.join("test/aliased.svg").is_file());

        let just_plain = vec!["test:plain".to_string()];
        let second = run_resolve(&just_plain, &out, &data)
            .ok()
            .expect("second resolve succeeds");
        assert_eq!(second.removed, vec!["test/aliased.svg".to_string()]);
        assert!(
            !out.join("test/aliased.svg").exists(),
            "a dropped selection's asset must be deleted, not just forgotten"
        );
        assert!(
            out.join("test/plain.svg").is_file(),
            "a still-selected asset survives"
        );

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn resolve_copies_a_custom_svg_and_tags_it_source_custom() {
        let data = scratch_dir("data-custom");
        write_pinned_fixture(&data, "test");
        let out = scratch_dir("out-custom");
        let asset_dir = scratch_dir("custom-asset");
        let asset_path = asset_dir.join("My Logo.svg");
        std::fs::write(
            &asset_path,
            r##"<svg width="32" height="32"><path fill="#ff0000" d="M0 0"/></svg>"##,
        )
        .unwrap();

        let ids = vec![format!("file:{}", asset_path.display())];
        let res = run_resolve(&ids, &out, &data)
            .ok()
            .expect("custom asset resolves");
        let entry = res
            .catalog
            .get("icons")
            .and_then(|i| i.get(&ids[0]))
            .expect("catalog carries the custom entry");
        assert_eq!(entry.get("source").and_then(Value::as_str), Some("custom"));
        assert!(entry.get("license").map(Value::is_null).unwrap_or(false));
        assert_eq!(
            entry.get("mono").and_then(Value::as_bool),
            Some(false),
            "a literal #ff0000 fill is multicolor"
        );
        assert_eq!(
            entry.get("file").and_then(Value::as_str),
            Some("custom/my-logo.svg")
        );
        assert!(out.join("custom/my-logo.svg").is_file());

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_dir_all(&asset_dir);
    }

    #[test]
    fn custom_asset_with_an_unsupported_extension_is_a_usage_error() {
        let data = scratch_dir("data-badext");
        write_pinned_fixture(&data, "test");
        let out = scratch_dir("out-badext");
        let asset_dir = scratch_dir("badext-asset");
        let asset_path = asset_dir.join("logo.gif");
        std::fs::write(&asset_path, b"not really a gif").unwrap();

        let ids = vec![format!("file:{}", asset_path.display())];
        match run_resolve(&ids, &out, &data) {
            Err(ResolveError::Usage(_)) => {}
            other => panic!("expected a usage error for an unsupported extension, got a different result (ok = {})", other.is_ok()),
        }

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_dir_all(&asset_dir);
    }

    // ── review fixup: path-traversal past --out (HIGH) ──

    #[test]
    fn a_dotdot_collection_is_refused_before_any_write() {
        let data = scratch_dir("data-traversal-dotdot");
        write_pinned_fixture(&data, "test");
        let out = scratch_dir("out-traversal-dotdot");
        let escaped = out
            .parent()
            .unwrap()
            .join(format!("pwned_{}.svg", std::process::id()));
        let _ = std::fs::remove_file(&escaped);

        // `"..:pwned"` has no `/` (skips the Custom-path branch) and no
        // `file:` prefix, so it reaches the Iconify arm as
        // `collection = ".."` — exactly the live-verified exploit
        // (`<out>/../pwned.svg` lands in --out's PARENT).
        let ids = vec!["..:pwned".to_string()];
        match run_resolve(&ids, &out, &data) {
            Err(ResolveError::Usage(msg)) => {
                assert!(
                    msg.contains("plain names"),
                    "expected the plain-name refusal, got: {msg}"
                );
            }
            other => panic!(
                "expected a usage error refusing the `..` collection, got ok = {}",
                other.is_ok()
            ),
        }
        assert!(
            !escaped.exists(),
            "a `..` collection must never write outside --out"
        );

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn a_slash_in_a_name_is_refused() {
        let data = scratch_dir("data-traversal-slash");
        write_pinned_fixture(&data, "test");
        let out = scratch_dir("out-traversal-slash");

        // A literal `/` anywhere in the id routes to the Custom-asset
        // branch upstream of the `<collection>:<name>` split (§C1's own
        // dispatch order), so the meaningful "path separator in a name"
        // case for the Iconify branch is a backslash — not a path
        // separator on this platform, so `id.contains('/')` doesn't catch
        // it, but `validate_plain_name` must.
        let ids = vec!["test:pwned\\..\\escaped".to_string()];
        match run_resolve(&ids, &out, &data) {
            Err(ResolveError::Usage(msg)) => {
                assert!(
                    msg.contains("plain names"),
                    "expected the plain-name refusal, got: {msg}"
                );
            }
            other => panic!(
                "expected a usage error refusing the backslash-laden name, got ok = {}",
                other.is_ok()
            ),
        }

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn prune_never_removes_a_path_outside_out() {
        let data = scratch_dir("data-prune-escape");
        write_pinned_fixture(&data, "test");
        let out = scratch_dir("out-prune-escape");
        std::fs::create_dir_all(&out).unwrap();

        // Seed a catalog.json as if from a tampered/pre-fix legacy build:
        // its `file` value is itself a traversal. `run_resolve` must never
        // produce a catalog shaped like this today (the write-side checks
        // above prevent it) — this simulates one arriving some other way
        // (a hand edit, a defect elsewhere) reaching the PRUNE path.
        let escaped_name = format!("escaped_{}.svg", std::process::id());
        let escaped_rel = format!("../{escaped_name}");
        let escaped_path = out.parent().unwrap().join(&escaped_name);
        std::fs::write(&escaped_path, "<svg/>").unwrap();
        std::fs::write(
            out.join("catalog.json"),
            format!(
                r#"{{"schemaVersion":0,"icons":{{"evil":{{"file":"{escaped_rel}","mono":true,"source":"custom","license":null}}}}}}"#
            ),
        )
        .unwrap();

        let ids = vec!["test:plain".to_string()];
        let res = run_resolve(&ids, &out, &data)
            .ok()
            .expect("resolve still succeeds for the legitimate selection");

        assert!(
            escaped_path.is_file(),
            "a catalog entry pointing outside --out must survive pruning"
        );
        assert!(
            !res.removed.contains(&escaped_rel),
            "the escaped entry must not be reported as removed"
        );
        assert!(
            res.skipped.contains(&escaped_rel),
            "the escaped entry must be reported as skipped/refused instead: {:?}",
            res.skipped
        );

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&out);
        let _ = std::fs::remove_file(&escaped_path);
    }

    // ── review fixup: style-declared colour (MEDIUM) ──

    #[test]
    fn a_style_attribute_fill_makes_the_asset_multicolor() {
        assert!(
            !detect_mono("<path style=\"fill:#ff0000\" d=\"M0 0\"/>"),
            "a literal colour in a style attribute must not be tagged mono"
        );
        assert!(
            !detect_mono("<style>path{fill:#00ff00;}</style><path d=\"M0 0\"/>"),
            "a literal colour in a <style> block must not be tagged mono"
        );
        assert!(
            detect_mono("<path style=\"fill:currentColor;stroke:none\" d=\"M0 0\"/>"),
            "an allow-listed token in a style attribute stays mono"
        );
    }
}
