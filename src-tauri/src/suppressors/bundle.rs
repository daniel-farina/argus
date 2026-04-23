// ARGUS_SELF_EXCLUDE
//! Minified bundles (any line longer than 500 chars) get code-pattern
//! rules demoted unless at least two independent rules fire on the same
//! file. Bundlers inline lots of third-party code and the patterns we
//! look for are common there.

use crate::detectors::ScanContext;
use crate::rules::{RuleHit, Severity};
use crate::suppressors::Suppressor;

pub struct BundleSuppressor;

impl Suppressor for BundleSuppressor {
    fn id(&self) -> &'static str {
        "bundle"
    }
    fn review(&self, ctx: &ScanContext, hits: Vec<RuleHit>) -> Vec<RuleHit> {
        if !ctx.is_bundle {
            return hits;
        }
        // Count unique rule ids among code-pattern rules only.
        let code_rule_hits: Vec<&RuleHit> = hits
            .iter()
            .filter(|h| !h.rule_id.starts_with("PKG") && !h.rule_id.starts_with("TYPO"))
            .collect();
        let unique: std::collections::HashSet<&str> =
            code_rule_hits.iter().map(|h| h.rule_id.as_str()).collect();
        let multi_rule = unique.len() >= 2;

        hits.into_iter()
            .filter_map(|mut h| {
                if h.rule_id.starts_with("PKG") || h.rule_id.starts_with("TYPO") {
                    return Some(h);
                }
                if multi_rule && h.severity as u8 >= Severity::High as u8 {
                    return Some(h);
                }
                // Demote single-rule matches in bundles aggressively.
                if h.severity as u8 >= Severity::Medium as u8 {
                    h.severity = Severity::Low;
                    h.title = format!("{} (demoted: single match in minified bundle)", h.title);
                    Some(h)
                } else {
                    None
                }
            })
            .collect()
    }
}
