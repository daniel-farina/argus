// ARGUS_SELF_EXCLUDE
//! Flags high-Shannon-entropy blobs embedded inside otherwise readable code.
//! Minified bundles are naturally high-entropy per-character but repeat
//! patterns; a single giant quoted base64 string with entropy > 5.0 and
//! no line breaks is what we want to catch.

use crate::detectors::{Detector, ScanContext};
use crate::rules::{build_hit_raw, Confidence, RuleHit, Severity};

pub struct EntropyDetector;

const MIN_BLOB_LEN: usize = 256;
const HIGH_ENTROPY: f64 = 4.8;

impl Detector for EntropyDetector {
    fn id(&self) -> &'static str {
        "entropy"
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<RuleHit> {
        if !matches!(
            ctx.ext,
            "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "py" | "rb"
        ) {
            return Vec::new();
        }
        if ctx.is_bundle || ctx.is_sourcemap {
            // Don't run this on known-minified payloads; the calling
            // suppressor already downgrades bundles.
            return Vec::new();
        }
        let mut hits = Vec::new();
        for (start, end, blob) in find_long_quoted_blobs(ctx.content) {
            if blob.len() < MIN_BLOB_LEN {
                continue;
            }
            let entropy = shannon_entropy(blob);
            if entropy < HIGH_ENTROPY {
                continue;
            }
            if !looks_like_base64_or_hex(blob) {
                continue;
            }
            hits.push(build_hit_raw(
                "ENT001".into(),
                format!(
                    "High-entropy {} blob ({} chars, H={:.2})",
                    if blob.chars().all(|c| c.is_ascii_hexdigit() || c == '\\') {
                        "hex"
                    } else {
                        "base64-like"
                    },
                    blob.len(),
                    entropy
                ),
                Severity::Medium,
                Confidence::Medium,
                ctx.content,
                start,
                end,
                Some(blob.chars().take(200).collect()),
            ));
        }
        hits
    }
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let mut h = 0.0;
    let t = total as f64;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = *c as f64 / t;
        h -= p * p.log2();
    }
    h
}

fn find_long_quoted_blobs(s: &str) -> Vec<(usize, usize, &str)> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'"' || q == b'\'' || q == b'`' {
            // Scan for the matching quote, no escape handling past \\.
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() {
                if bytes[j] == q && bytes[j - 1] != b'\\' {
                    break;
                }
                j += 1;
            }
            if j > start + MIN_BLOB_LEN / 2 {
                if let Ok(inner) = std::str::from_utf8(&bytes[start..j]) {
                    if !inner.contains('\n') {
                        out.push((start, j, inner));
                    }
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

fn looks_like_base64_or_hex(s: &str) -> bool {
    let mut base64 = 0;
    let mut hex = 0;
    let total = s.len();
    if total == 0 {
        return false;
    }
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            base64 += 1;
        }
        if c.is_ascii_hexdigit() {
            hex += 1;
        }
    }
    let b_ratio = base64 as f64 / total as f64;
    let h_ratio = hex as f64 / total as f64;
    b_ratio > 0.92 || h_ratio > 0.92
}
