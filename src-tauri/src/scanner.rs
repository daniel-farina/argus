// ARGUS_SELF_EXCLUDE
//! File-level scan entry point. Builds a ScanContext, runs the detector
//! pipeline, then the suppressor pipeline, and packages the result as a
//! Detection.

use crate::detectors::{self, ScanContext};
use crate::rules::{RuleHit, Severity};
use crate::suppressors;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_SCAN_SIZE: u64 = 8 * 1024 * 1024;
pub const BUNDLE_LINE_THRESHOLD: usize = 500;
pub const SELF_EXCLUDE_MARKER: &str = "ARGUS_SELF_EXCLUDE";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub top_severity: Severity,
    pub hits: Vec<RuleHit>,
    pub timestamp: String,
    pub action: String,
}

pub fn file_ext(path: &Path) -> String {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn sha256_of(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

pub fn top_severity(hits: &[RuleHit]) -> Severity {
    let mut top = Severity::Info;
    for h in hits {
        if severity_rank(h.severity) > severity_rank(top) {
            top = h.severity;
        }
    }
    top
}

pub fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

pub fn is_path_excluded(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/.argus/") || s.contains("/argus/src-tauri/src/")
}

pub fn scan_file(path: &Path) -> anyhow::Result<Option<Detection>> {
    if is_path_excluded(path) {
        return Ok(None);
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_SCAN_SIZE {
        return Ok(None);
    }

    let ext = file_ext(path);
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    if content.contains(SELF_EXCLUDE_MARKER) {
        return Ok(None);
    }

    let ctx = build_context(path, &content, &ext, meta.len());
    let mut hits = detectors::run_detectors(&ctx);
    hits = suppressors::run_suppressors(&ctx, hits);

    // Drop Info-severity hits from the final output - they're just noise.
    hits.retain(|h| severity_rank(h.severity) >= severity_rank(Severity::Low));
    if hits.is_empty() {
        return Ok(None);
    }

    let sha = sha256_of(path).unwrap_or_default();
    let top = top_severity(&hits);

    Ok(Some(Detection {
        id: format!(
            "{}-{}",
            chrono::Utc::now().timestamp_millis(),
            &sha[..8.min(sha.len())]
        ),
        path: path.display().to_string(),
        sha256: sha,
        size: meta.len(),
        top_severity: top,
        hits,
        timestamp: chrono::Utc::now().to_rfc3339(),
        action: "detected".to_string(),
    }))
}

fn build_context<'a>(
    path: &'a Path,
    content: &'a str,
    ext: &'a str,
    size: u64,
) -> ScanContext<'a> {
    let in_node_modules = path.to_string_lossy().contains("/node_modules/");
    let package_name = find_package_name(path);
    let is_first_party = !in_node_modules;

    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let is_declaration = name.ends_with(".d.ts");
    let is_sourcemap = name.ends_with(".map");
    let is_test_config = matches!(
        name,
        "karma.conf.js"
            | "karma.conf.cjs"
            | "jest.config.js"
            | "jest.config.cjs"
            | "jest.config.ts"
            | "webpack.config.js"
            | "webpack.config.cjs"
            | "rollup.config.js"
            | "rollup.config.cjs"
            | ".eslintrc.js"
            | ".eslintrc.cjs"
            | "eslint.config.js"
            | "eslint.config.cjs"
    );

    let mut max_line_len = 0;
    for line in content.lines() {
        let l = line.len();
        if l > max_line_len {
            max_line_len = l;
        }
    }
    let is_bundle = max_line_len > BUNDLE_LINE_THRESHOLD;
    let parent_package_json = find_parent_package_json(path);

    ScanContext {
        path,
        content,
        ext,
        size,
        in_node_modules,
        package_name,
        is_first_party,
        is_declaration,
        is_bundle,
        is_sourcemap,
        is_test_config,
        max_line_len,
        parent_package_json,
    }
}

fn find_package_name(path: &Path) -> Option<String> {
    let s = path.to_string_lossy();
    let needle = "/node_modules/";
    let idx = s.rfind(needle)?;
    let after = &s[idx + needle.len()..];
    let mut parts = after.splitn(3, '/');
    let first = parts.next()?;
    if first.starts_with('@') {
        if let Some(second) = parts.next() {
            return Some(format!("{}/{}", first, second));
        }
    }
    Some(first.to_string())
}

fn find_parent_package_json(path: &Path) -> Option<PathBuf> {
    let mut cur = path.parent();
    while let Some(d) = cur {
        let candidate = d.join("package.json");
        if candidate.exists() {
            return Some(candidate);
        }
        cur = d.parent();
    }
    None
}

pub fn scan_directory(root: &Path) -> Vec<Detection> {
    let mut out = Vec::new();
    let skip = [
        "node_modules", ".git", "target", "dist", "build", ".next",
        ".cache", ".argus",
    ];
    let walker = walkdir::WalkDir::new(root).follow_links(false).into_iter();
    for entry in walker.filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !skip.iter().any(|s| *s == name.as_ref())
    }) {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        if let Ok(Some(det)) = scan_file(entry.path()) {
            out.push(det);
        }
    }
    out
}

pub fn candidate_file(path: &Path) -> bool {
    let ext = file_ext(path);
    matches!(
        ext.as_str(),
        "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx"
            | "py" | "rb" | "go" | "rs" | "sh" | "bash" | "zsh"
            | "json" | "yaml" | "yml"
    )
}

pub fn normalize(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
