// DEVPROTECTOR_SELF_EXCLUDE
//! Drops regex-rule hits where the match falls inside a JS regex literal
//! (`/eval\(atob/`) or inside a backtick-quoted string that is clearly
//! a pattern (e.g. RegExp source). ESLint rules, linters, parsers,
//! security scanners themselves embed these literals.

use crate::detectors::ScanContext;
use crate::rules::RuleHit;
use crate::suppressors::Suppressor;

pub struct RegexLiteralSuppressor;

impl Suppressor for RegexLiteralSuppressor {
    fn id(&self) -> &'static str {
        "regex-literal"
    }
    fn review(&self, ctx: &ScanContext, hits: Vec<RuleHit>) -> Vec<RuleHit> {
        if !matches!(ctx.ext, "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx") {
            return hits;
        }
        let bytes = ctx.content.as_bytes();
        hits.into_iter()
            .filter(|h| {
                // Structural rules are position-independent.
                if h.rule_id.starts_with("PKG") || h.rule_id.starts_with("TYPO") {
                    return true;
                }
                let Some(off) = h.byte_offset else {
                    return true;
                };
                !is_inside_regex_literal(bytes, off)
            })
            .collect()
    }
}

/// Scan leftward from `pos` looking for an unmatched opening `/` that starts
/// a regex literal and doesn't belong to a comment or division. Conservative:
/// we look at the current line only.
fn is_inside_regex_literal(bytes: &[u8], pos: usize) -> bool {
    if pos >= bytes.len() {
        return false;
    }
    // Find the start of line.
    let mut start = pos;
    while start > 0 && bytes[start - 1] != b'\n' {
        start -= 1;
    }
    // Find the end of line.
    let mut end = pos;
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    let line = &bytes[start..end];
    let local_pos = pos - start;

    // Walk the line tracking string/regex context.
    let mut in_str: Option<u8> = None;
    let mut in_regex = false;
    let mut prev = b' ';
    let mut i = 0;
    while i < line.len() {
        let c = line[i];
        if let Some(q) = in_str {
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else if in_regex {
            if c == b'/' && prev != b'\\' {
                in_regex = false;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = Some(c);
        } else if c == b'/' {
            // heuristic: regex literal if preceded by operator / keyword / start-of-line
            let is_regex = matches!(
                prev,
                b'(' | b',' | b'=' | b':' | b'[' | b'!' | b'&' | b'|'
                    | b'?' | b'{' | b'}' | b';' | b'+' | b'-' | b'*' | b'~' | b'^'
                    | b' ' | b'\t'
            );
            if is_regex && i + 1 < line.len() && line[i + 1] != b'/' && line[i + 1] != b'*' {
                in_regex = true;
            }
        }

        // If our hit offset falls inside a regex literal we just opened,
        // signal true once we reach it.
        if i == local_pos && in_regex {
            return true;
        }

        prev = c;
        i += 1;
    }
    false
}
