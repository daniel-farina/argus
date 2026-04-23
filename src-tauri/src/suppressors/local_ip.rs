// DEVPROTECTOR_SELF_EXCLUDE
//! Calibrates JS012 exfil-host hits based on the matched URL:
//!   - localhost / RFC1918 private address -> drop entirely
//!     (tests, dev servers, docs constantly reference 127.0.0.1 / 10.x / ...)
//!   - other bare IPv4 URLs -> demote to Low severity, since developers
//!     reference public DNS (8.8.8.8), cloud metadata, and example IPs
//!     in tests all the time
//!   - named hostile hosts (transfer.sh, webhook.site, requestbin,
//!     ngrok, duckdns, glitch.me, pastebin) stay at High

use crate::detectors::ScanContext;
use crate::rules::{RuleHit, Severity};
use crate::suppressors::Suppressor;

pub struct LocalIpSuppressor;

impl Suppressor for LocalIpSuppressor {
    fn id(&self) -> &'static str {
        "local-ip"
    }
    fn review(&self, _ctx: &ScanContext, hits: Vec<RuleHit>) -> Vec<RuleHit> {
        hits.into_iter()
            .filter_map(|mut h| {
                if h.rule_id != "JS012" {
                    return Some(h);
                }
                let matched = h.matched.clone().unwrap_or_default();
                if is_local_url(&matched) {
                    return None;
                }
                if looks_like_raw_ip(&matched) {
                    // Demote to Low: still appears in the detection feed but
                    // doesn't panic the user.
                    h.severity = Severity::Low;
                    h.title = format!("{} (raw-IP URL, demoted)", h.title);
                }
                Some(h)
            })
            .collect()
    }
}

fn looks_like_raw_ip(m: &str) -> bool {
    let s = m.to_ascii_lowercase();
    let s = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(&s);
    let host = s.split(|c: char| c == '/' || c == ':' || c == '?' || c == '#').next().unwrap_or(s);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_local_url(m: &str) -> bool {
    let s = m.to_ascii_lowercase();
    // Strip scheme.
    let s = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")).unwrap_or(&s).to_string();
    // Take host portion (up to first slash, colon, or end).
    let host: &str = s
        .split(|c: char| c == '/' || c == ':' || c == '?' || c == '#')
        .next()
        .unwrap_or(&s);
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
        return true;
    }
    // Prefix-based private/local detection - handles malformed octets in
    // test files like "http://192.168.0.285".
    let prefixes = ["127.", "10.", "192.168.", "169.254.", "0.0.0.0"];
    for p in &prefixes {
        if host.starts_with(p) {
            return true;
        }
    }
    // 172.16.0.0/12 - second octet must be 16-31.
    if let Some(rest) = host.strip_prefix("172.") {
        if let Some(second_str) = rest.split('.').next() {
            if let Ok(n) = second_str.parse::<u16>() {
                if (16..=31).contains(&n) {
                    return true;
                }
            }
        }
    }
    // Parse IPv4 octets strictly for the uninteresting case.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let octets: Option<Vec<u8>> = parts.iter().map(|p| p.parse::<u8>().ok()).collect();
    if octets.is_none() {
        return false;
    }
    false
}
