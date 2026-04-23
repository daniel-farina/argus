// ARGUS_SELF_EXCLUDE
//! Persistent store of detections the user has explicitly marked as
//! false positives. A dismissal is keyed by (sha256 prefix, rule_id) so
//! the same content triggering the same rule never re-alerts, but a
//! different file or a different rule on the same file still fires.

use chrono::Utc;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dismissal {
    pub sha256: String,
    pub rule_id: String,
    pub path: String,
    pub note: Option<String>,
    pub dismissed_at: String,
    pub source: String, // "user" | "claude"
}

pub fn dismissals_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".argus").join("dismissals.json")
}

pub fn key(sha: &str, rule_id: &str) -> String {
    let head = &sha[..16.min(sha.len())];
    format!("{}:{}", head, rule_id)
}

fn load_from_disk() -> Vec<Dismissal> {
    let p = dismissals_path();
    if !p.exists() {
        return Vec::new();
    }
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_to_disk(items: &[Dismissal]) -> anyhow::Result<()> {
    let p = dismissals_path();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&p, serde_json::to_vec_pretty(items)?)?;
    Ok(())
}

static CACHE: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| {
    let items = load_from_disk();
    let set: HashSet<String> = items
        .iter()
        .map(|d| key(&d.sha256, &d.rule_id))
        .collect();
    Mutex::new(set)
});

pub fn is_dismissed(sha: &str, rule_id: &str) -> bool {
    CACHE.lock().contains(&key(sha, rule_id))
}

pub fn list() -> Vec<Dismissal> {
    load_from_disk()
}

pub fn add(
    path: &str,
    sha256: &str,
    rule_id: &str,
    note: Option<String>,
    source: &str,
) -> anyhow::Result<Dismissal> {
    let mut all = load_from_disk();
    // de-dupe
    all.retain(|d| !(d.sha256 == sha256 && d.rule_id == rule_id));
    let d = Dismissal {
        sha256: sha256.to_string(),
        rule_id: rule_id.to_string(),
        path: path.to_string(),
        note,
        dismissed_at: Utc::now().to_rfc3339(),
        source: source.to_string(),
    };
    all.push(d.clone());
    save_to_disk(&all)?;
    CACHE.lock().insert(key(sha256, rule_id));
    Ok(d)
}

pub fn remove(sha256: &str, rule_id: &str) -> anyhow::Result<()> {
    let mut all = load_from_disk();
    all.retain(|d| !(d.sha256 == sha256 && d.rule_id == rule_id));
    save_to_disk(&all)?;
    CACHE.lock().remove(&key(sha256, rule_id));
    Ok(())
}
