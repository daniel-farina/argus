// ARGUS_SELF_EXCLUDE
//! Runs the declarative regex rule set from `crate::rules::RULES`.

use crate::detectors::{Detector, ScanContext};
use crate::rules::{build_hit, RuleHit, RULES};

pub struct RegexRulesDetector;

const PER_RULE_CAP: usize = 5;

impl Detector for RegexRulesDetector {
    fn id(&self) -> &'static str {
        "regex"
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<RuleHit> {
        let mut hits: Vec<RuleHit> = Vec::new();
        for rule in RULES.iter() {
            if !rule.file_exts.is_empty() && !rule.file_exts.contains(&ctx.ext) {
                continue;
            }
            for m in rule.pattern.find_iter(ctx.content).take(PER_RULE_CAP) {
                hits.push(build_hit(
                    rule.id,
                    rule.title,
                    rule.severity,
                    rule.confidence,
                    ctx.content,
                    m.start(),
                    m.end(),
                ));
            }
        }
        hits
    }
}
