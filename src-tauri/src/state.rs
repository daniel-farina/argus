use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::config::{self, Config};
use crate::scanner::Detection;
use crate::watcher::{WatchManager, WatchMutex};

pub const DETECTION_BUFFER: usize = 500;
pub const ACTIVITY_BUFFER: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub timestamp: String,
    pub kind: String,
    pub path: String,
    pub size: u64,
    pub duration_ms: u64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActivityStats {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub detections_count: u64,
    pub quarantined_count: u64,
    pub skipped_count: u64,
    pub last_path: Option<String>,
    pub last_kind: Option<String>,
    pub last_ts: Option<String>,
    pub watched_count: usize,
    pub started_at: Option<String>,
    pub current_scan: Option<String>,
}

pub struct AppState {
    pub config: Mutex<Config>,
    pub detections: Mutex<VecDeque<Detection>>,
    pub watch: WatchMutex,
    pub activity: Mutex<VecDeque<ActivityEvent>>,
    pub stats: Mutex<ActivityStats>,
    pub boot: Instant,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        let cfg = config::load();
        let stats = ActivityStats {
            started_at: Some(chrono::Utc::now().to_rfc3339()),
            ..Default::default()
        };
        Arc::new(Self {
            config: Mutex::new(cfg),
            detections: Mutex::new(VecDeque::with_capacity(DETECTION_BUFFER)),
            watch: Mutex::new(WatchManager::new()),
            activity: Mutex::new(VecDeque::with_capacity(ACTIVITY_BUFFER)),
            stats: Mutex::new(stats),
            boot: Instant::now(),
        })
    }

    pub fn push_detection(&self, det: Detection) {
        let mut d = self.detections.lock();
        if d.len() >= DETECTION_BUFFER {
            d.pop_front();
        }
        d.push_back(det);
    }

    pub fn push_activity(&self, event: ActivityEvent) {
        {
            let mut s = self.stats.lock();
            s.files_scanned = s.files_scanned.saturating_add(1);
            s.bytes_scanned = s.bytes_scanned.saturating_add(event.size);
            match event.kind.as_str() {
                "detected" => s.detections_count = s.detections_count.saturating_add(1),
                "quarantined" => s.quarantined_count = s.quarantined_count.saturating_add(1),
                "skipped" => s.skipped_count = s.skipped_count.saturating_add(1),
                _ => {}
            }
            s.last_path = Some(event.path.clone());
            s.last_kind = Some(event.kind.clone());
            s.last_ts = Some(event.timestamp.clone());
        }
        let mut a = self.activity.lock();
        if a.len() >= ACTIVITY_BUFFER {
            a.pop_front();
        }
        a.push_back(event);
    }

    pub fn set_current_scan(&self, path: Option<String>) {
        self.stats.lock().current_scan = path;
    }

    pub fn set_watched_count(&self, n: usize) {
        self.stats.lock().watched_count = n;
    }

    pub fn persist(&self) {
        let cfg = self.config.lock().clone();
        if let Err(e) = config::save(&cfg) {
            tracing::error!("config save failed: {e}");
        }
    }
}
