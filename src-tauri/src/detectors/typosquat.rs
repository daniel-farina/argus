// ARGUS_SELF_EXCLUDE
//! Flags package.json dependencies whose name is a distance-1 typo
//! of a popular package name. Typical supply-chain trick.

use crate::detectors::{Detector, ScanContext};
use crate::rules::{build_hit_raw, Confidence, RuleHit, Severity, POPULAR_PACKAGES};

pub struct TyposquatDetector;

impl Detector for TyposquatDetector {
    fn id(&self) -> &'static str {
        "typosquat"
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<RuleHit> {
        if ctx.path.file_name().and_then(|n| n.to_str()) != Some("package.json") {
            return Vec::new();
        }
        // Typosquat detection only runs on the developer's own package.json.
        // Transitive deps already inside node_modules have been vetted by
        // npm's registry and by the root package author; flagging them
        // produces endless false positives (eclint vs eslint, matcha vs mocha).
        if ctx.in_node_modules {
            return Vec::new();
        }
        let v: serde_json::Value = match serde_json::from_str(ctx.content) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let mut hits = Vec::new();
        for field in ["dependencies", "devDependencies"] {
            if let Some(deps) = v.get(field).and_then(|d| d.as_object()) {
                for name in deps.keys() {
                    if POPULAR_PACKAGES.contains(&name.as_str()) {
                        continue;
                    }
                    if name.starts_with('@') {
                        continue; // scoped packages: typosquat detection is noisy
                    }
                    if let Some((pop, dist)) = nearest_popular(name) {
                        let (sev, conf) = if dist == 1 {
                            (Severity::High, Confidence::Medium)
                        } else {
                            (Severity::Medium, Confidence::Low)
                        };
                        let offset = ctx.content.find(name.as_str()).unwrap_or(0);
                        hits.push(build_hit_raw(
                            "TYPO001".into(),
                            format!(
                                "Possible typosquat of '{}' (edit distance {}) in {}: '{}'",
                                pop, dist, field, name
                            ),
                            sev,
                            conf,
                            ctx.content,
                            offset,
                            offset + name.len(),
                            Some(name.clone()),
                        ));
                    }
                }
            }
        }
        hits
    }
}

fn nearest_popular(name: &str) -> Option<(&'static str, usize)> {
    if name.len() < 5 {
        return None;
    }
    for pop in POPULAR_PACKAGES {
        if pop.len() < 5 {
            continue;
        }
        if (pop.len() as isize - name.len() as isize).abs() > 2 {
            continue;
        }
        let d = levenshtein(name, pop);
        if d == 1 {
            return Some((pop, d));
        }
        if d == 2 && pop.len() >= 10 && name.len() >= 10 {
            return Some((pop, d));
        }
    }
    None
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut cur = vec![0usize; n + 1];
    for i in 1..=m {
        cur[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[n]
}
