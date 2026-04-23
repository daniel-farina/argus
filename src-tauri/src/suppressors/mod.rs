// DEVPROTECTOR_SELF_EXCLUDE
//! Pipeline of Suppressors that run after all Detectors have produced
//! raw hits. Each suppressor can drop or downgrade hits based on broader
//! file context (is this a .d.ts typings file? is this inside a known-good
//! OSS package? is the match sitting inside a regex literal?).

pub mod bundle;
pub mod declaration;
pub mod known_good;
pub mod local_ip;
pub mod regex_literal;

use crate::detectors::ScanContext;
use crate::rules::RuleHit;

pub trait Suppressor: Send + Sync {
    fn id(&self) -> &'static str;
    fn review(&self, ctx: &ScanContext, hits: Vec<RuleHit>) -> Vec<RuleHit>;
}

pub fn registered_suppressors() -> Vec<Box<dyn Suppressor>> {
    vec![
        Box::new(regex_literal::RegexLiteralSuppressor),
        Box::new(declaration::DeclarationFileSuppressor),
        Box::new(bundle::BundleSuppressor),
        Box::new(known_good::KnownGoodPackageSuppressor),
        Box::new(local_ip::LocalIpSuppressor),
    ]
}

pub fn run_suppressors(ctx: &ScanContext, hits: Vec<RuleHit>) -> Vec<RuleHit> {
    let mut current = hits;
    for s in registered_suppressors() {
        current = s.review(ctx, current);
    }
    current
}
