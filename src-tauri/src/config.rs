use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub folders: BTreeSet<String>,
    pub protection_enabled: bool,
    pub auto_kill_processes: bool,
    pub auto_quarantine: bool,
}

impl Config {
    pub fn defaults() -> Self {
        // Default to detect-only so users can review detections before
        // enabling destructive actions.
        Self {
            folders: BTreeSet::new(),
            protection_enabled: true,
            auto_kill_processes: false,
            auto_quarantine: false,
        }
    }
}

pub fn config_dir() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(".devprotector")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

pub fn load() -> Config {
    let p = config_path();
    if !p.exists() {
        return Config::defaults();
    }
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(Config::defaults)
}

pub fn save(cfg: &Config) -> anyhow::Result<()> {
    let dir = config_dir();
    fs::create_dir_all(&dir)?;
    fs::write(config_path(), serde_json::to_vec_pretty(cfg)?)?;
    Ok(())
}
