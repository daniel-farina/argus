// ARGUS_SELF_EXCLUDE
//! Modular detection pipeline. Each Detector inspects a ScanContext and
//! returns zero or more RuleHits. The runner concatenates results, then
//! a chain of Suppressors can downgrade or drop hits based on file-level
//! context (e.g. "this is a .d.ts declaration file, drop code-pattern hits").

pub mod entropy;
pub mod package_json;
pub mod regex_rules;
pub mod typosquat;

use crate::rules::RuleHit;

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, ctx: &ScanContext) -> Vec<RuleHit>;
}

pub struct ScanContext<'a> {
    pub path: &'a std::path::Path,
    pub content: &'a str,
    pub ext: &'a str,
    pub size: u64,
    pub in_node_modules: bool,
    /// Name of the npm package that contains this file, if the path is
    /// `.../node_modules/<name>/...` or `.../node_modules/@scope/<name>/...`.
    pub package_name: Option<String>,
    pub is_first_party: bool,
    /// True for .d.ts TypeScript declaration files (type-only, no runtime code).
    pub is_declaration: bool,
    /// True for minified bundles (any line > 500 chars).
    pub is_bundle: bool,
    /// True for .map sourcemaps.
    pub is_sourcemap: bool,
    /// True for test / build config files like karma.conf.js, jest.config.js, webpack.config.js.
    pub is_test_config: bool,
    pub max_line_len: usize,
    /// The parent package.json path (if any) walking upward.
    pub parent_package_json: Option<std::path::PathBuf>,
}

pub fn registered_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(regex_rules::RegexRulesDetector),
        Box::new(package_json::PackageJsonDetector),
        Box::new(entropy::EntropyDetector),
        Box::new(typosquat::TyposquatDetector),
    ]
}

pub fn run_detectors(ctx: &ScanContext) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    for d in registered_detectors() {
        let found = d.detect(ctx);
        hits.extend(found);
    }
    hits
}
