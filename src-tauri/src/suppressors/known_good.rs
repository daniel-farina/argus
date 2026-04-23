// ARGUS_SELF_EXCLUDE
//! When a file lives inside `node_modules/<pkg>/...` where `<pkg>` is on
//! a curated allowlist of ultra-popular OSS packages, demote code-pattern
//! hits by one severity level. The allowlist is intentionally short and
//! covers packages that inherently contain suspicious-looking strings
//! (JS parsers, linters, minifiers, spec shims).
//!
//! We keep PKG-* (package.json structural) and TYPO-* (dependency name)
//! rules at full severity even inside allowlisted packages so a supply
//! chain takeover of `eslint` still surfaces the malicious postinstall.

use crate::detectors::ScanContext;
use crate::rules::{Severity, RuleHit, KNOWN_GOOD_PACKAGES};
use crate::suppressors::Suppressor;

pub struct KnownGoodPackageSuppressor;

impl Suppressor for KnownGoodPackageSuppressor {
    fn id(&self) -> &'static str {
        "known-good"
    }
    fn review(&self, ctx: &ScanContext, hits: Vec<RuleHit>) -> Vec<RuleHit> {
        let Some(pkg) = ctx.package_name.as_deref() else {
            return hits;
        };
        if !KNOWN_GOOD_PACKAGES.contains(&pkg) {
            return hits;
        }
        hits.into_iter()
            .filter_map(|mut h| {
                // Keep structural rules at full severity.
                if h.rule_id.starts_with("PKG") || h.rule_id.starts_with("TYPO") {
                    return Some(h);
                }
                h.severity = demote(h.severity);
                h.title = format!("{} (in allowlisted package '{}')", h.title, pkg);
                // Drop hits that fell below informational.
                if (h.severity as u8) == 0 && !h.rule_id.starts_with("PKG") {
                    return None;
                }
                Some(h)
            })
            .collect()
    }
}

fn demote(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::Low,
        Severity::High => Severity::Low,
        Severity::Medium => Severity::Info,
        _ => Severity::Info,
    }
}
