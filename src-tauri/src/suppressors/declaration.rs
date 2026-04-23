// DEVPROTECTOR_SELF_EXCLUDE
//! TypeScript .d.ts declaration files contain type definitions only.
//! They mention identifiers like `eval`, `Buffer`, etc. but do not run
//! any code. Drop all regex code-pattern hits on declaration files.

use crate::detectors::ScanContext;
use crate::rules::RuleHit;
use crate::suppressors::Suppressor;

pub struct DeclarationFileSuppressor;

impl Suppressor for DeclarationFileSuppressor {
    fn id(&self) -> &'static str {
        "decl-file"
    }
    fn review(&self, ctx: &ScanContext, hits: Vec<RuleHit>) -> Vec<RuleHit> {
        if !ctx.is_declaration {
            return hits;
        }
        hits.into_iter()
            .filter(|h| h.rule_id.starts_with("PKG") || h.rule_id.starts_with("TYPO"))
            .collect()
    }
}
