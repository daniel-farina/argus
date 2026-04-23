use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::scanner::Detection;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub quarantine_path: String,
    pub sha256: String,
    pub size: u64,
    pub timestamp: String,
    pub detection: Detection,
}

pub fn quarantine_root() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".devprotector").join("quarantine")
}

fn index_path() -> PathBuf {
    quarantine_root().join("index.json")
}

pub fn ensure_dirs() -> anyhow::Result<()> {
    fs::create_dir_all(quarantine_root())?;
    Ok(())
}

fn load_index() -> Vec<QuarantineEntry> {
    let p = index_path();
    if !p.exists() {
        return Vec::new();
    }
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_index(items: &[QuarantineEntry]) -> anyhow::Result<()> {
    let p = index_path();
    fs::create_dir_all(p.parent().unwrap())?;
    fs::write(&p, serde_json::to_vec_pretty(items)?)?;
    Ok(())
}

pub fn list() -> Vec<QuarantineEntry> {
    load_index()
}

pub fn quarantine(detection: &Detection) -> anyhow::Result<QuarantineEntry> {
    ensure_dirs()?;
    let src = PathBuf::from(&detection.path);
    let meta = fs::metadata(&src)?;
    let id = format!(
        "{}-{}",
        Utc::now().timestamp_millis(),
        &detection.sha256[..8.min(detection.sha256.len())]
    );
    let filename = src
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());
    let dest = quarantine_root().join(format!("{}__{}", id, filename));

    // Move the file; if cross-device, fall back to copy + remove.
    if let Err(_) = fs::rename(&src, &dest) {
        fs::copy(&src, &dest)?;
        fs::remove_file(&src)?;
    }
    // Make quarantined file non-executable and hard to run accidentally.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&dest)?.permissions();
        perms.set_mode(0o400);
        let _ = fs::set_permissions(&dest, perms);
    }

    let entry = QuarantineEntry {
        id,
        original_path: detection.path.clone(),
        quarantine_path: dest.display().to_string(),
        sha256: detection.sha256.clone(),
        size: meta.len(),
        timestamp: Utc::now().to_rfc3339(),
        detection: detection.clone(),
    };

    let mut idx = load_index();
    idx.push(entry.clone());
    save_index(&idx)?;
    Ok(entry)
}

pub fn restore(id: &str) -> anyhow::Result<()> {
    let mut idx = load_index();
    let pos = idx
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| anyhow::anyhow!("quarantine id not found"))?;
    let entry = idx.remove(pos);
    let src = Path::new(&entry.quarantine_path);
    let dest = Path::new(&entry.original_path);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(src) {
            let mut perms = meta.permissions();
            perms.set_mode(0o644);
            let _ = fs::set_permissions(src, perms);
        }
    }
    if let Err(_) = fs::rename(src, dest) {
        fs::copy(src, dest)?;
        fs::remove_file(src)?;
    }
    save_index(&idx)?;
    Ok(())
}

pub fn delete(id: &str) -> anyhow::Result<()> {
    let mut idx = load_index();
    let pos = idx
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| anyhow::anyhow!("quarantine id not found"))?;
    let entry = idx.remove(pos);
    let p = Path::new(&entry.quarantine_path);
    if p.exists() {
        let _ = fs::remove_file(p);
    }
    save_index(&idx)?;
    Ok(())
}
