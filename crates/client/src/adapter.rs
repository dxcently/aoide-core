//! Adapters — thin per-agent consumers of the aoided neutral event stream.
//!
//! An adapter translates events into agent-facing dispatches. Subscriptions are
//! default-deny per class (entities/aoided): the adapter's allow-list arrives
//! via `$AOIDE_ADAPTER_SUBSCRIBE` (comma-separated event classes). Forwarded
//! notification payloads carry ONLY `{ actionId, appName }` — never the raw
//! notification body — so an app title can never reach the agent as an
//! instruction (the security boundary).
//!
//! Moved wholesale from root `src/adapter.rs` (Phase 4b restructure,
//! docs/architecture/PACKAGE-LAYOUT.md); re-exported at the old
//! `crate::adapter::{run_melete, subscription_from_env, safe_notification}`
//! path so every existing caller is untouched. `Door`/`EventClass`/
//! `Subscription`/`audit`/`default_audit_log` now resolve straight from
//! `aoide_protocol` — the root `daemon.rs` shim this used to go through
//! (`crate::daemon::{self, EventClass, Subscription}`) was itself only a
//! Phase 4a re-export of these same `aoide_protocol` types, so this client
//! crate reaches for them directly rather than through that root shim.

use aoide_protocol::{audit, default_audit_log, Door, EventClass, Subscription};
use serde_json::json;

/// Parse the `$AOIDE_ADAPTER_SUBSCRIBE` allow-list into a [`Subscription`].
/// Unknown class names are ignored; nothing is allowed by default.
pub fn subscription_from_env() -> (Subscription, Vec<String>) {
    let mut sub = Subscription::new();
    let mut allowed: Vec<String> = Vec::new();
    if let Ok(raw) = std::env::var("AOIDE_ADAPTER_SUBSCRIBE") {
        for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(class) = parse_class(name) {
                sub.allow(class);
                allowed.push(name.to_string());
            }
        }
    }
    (sub, allowed)
}

fn parse_class(name: &str) -> Option<EventClass> {
    match name {
        "audit" => Some(EventClass::Audit),
        "gate" => Some(EventClass::Gate),
        "rice" => Some(EventClass::Rice),
        "content" => Some(EventClass::Content),
        "notification" => Some(EventClass::Notification),
        _ => None,
    }
}

/// A forwarded notification as an adapter is allowed to see it: metadata only.
/// The raw body is deliberately absent — it never crosses this boundary.
pub fn safe_notification(action_id: &str, app_name: &str) -> serde_json::Value {
    json!({ "actionId": action_id, "appName": app_name })
}

/// Run the melete-adapter skeleton: resolve the subscription from env, prove
/// the default-deny boundary and the metadata-only notification shape, and
/// return a status document.
pub fn run_melete() -> serde_json::Value {
    let (sub, allowed) = subscription_from_env();

    // Security-boundary proof: a notification is only delivered as metadata,
    // and only if `notification` was explicitly subscribed.
    let notif_allowed = sub.accepts(EventClass::Notification);
    let sample = safe_notification("dismiss", "Telegram");

    let _ = audit(
        &default_audit_log(),
        Door::Daemon,
        EventClass::Audit,
        "adapter.melete",
        "started",
        "melete-adapter skeleton online",
    );

    json!({
        "process": "adapter.melete",
        "state": "skeleton",
        "subscribed": allowed,
        "subscriptionModel": "default-deny-per-class",
        "notification": {
            "deliveredAsMetadataOnly": true,
            "carriesRawBody": false,
            "allowed": notif_allowed,
            "shape": sample
        }
    })
}
