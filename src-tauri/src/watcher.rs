use notify::event::EventKind;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

use crate::processes::kill_processes_using;
use crate::quarantine;
use crate::scanner::{self, Detection};
use crate::state::{ActivityEvent, AppState};

pub struct WatchManager {
    watcher: Option<RecommendedWatcher>,
    pub watched: HashSet<PathBuf>,
    pub recent: HashMap<PathBuf, Instant>,
}

impl WatchManager {
    pub fn new() -> Self {
        Self {
            watcher: None,
            watched: HashSet::new(),
            recent: HashMap::new(),
        }
    }
}

/// Spawn the background watcher pump. Called once on startup.
/// Returns a handle that the app can use to add/remove watched folders.
pub fn spawn(app: AppHandle, state: Arc<AppState>) {
    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();

    let watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    });

    let watcher = match watcher {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("failed to create watcher: {e}");
            return;
        }
    };

    {
        let mut mgr = state.watch.lock();
        mgr.watcher = Some(watcher);
    }

    // Rehydrate any previously configured folders.
    let existing: Vec<String> = state.config.lock().folders.iter().cloned().collect();
    for f in existing {
        let _ = add_path(&state, Path::new(&f));
    }

    std::thread::spawn(move || {
        let dedup_window = Duration::from_millis(750);
        while let Ok(evt) = rx.recv() {
            let Ok(evt) = evt else { continue };
            let interesting = matches!(
                evt.kind,
                EventKind::Create(_) | EventKind::Modify(_)
            );
            if !interesting {
                continue;
            }
            for path in evt.paths {
                if !scanner::candidate_file(&path) {
                    continue;
                }
                if scanner::is_path_excluded(&path) {
                    continue;
                }

                {
                    let mut mgr = state.watch.lock();
                    let now = Instant::now();
                    mgr.recent.retain(|_, t| now.duration_since(*t) < dedup_window);
                    if let Some(t) = mgr.recent.get(&path) {
                        if now.duration_since(*t) < dedup_window {
                            continue;
                        }
                    }
                    mgr.recent.insert(path.clone(), now);
                }

                handle_file(&app, &state, &path);
            }
        }
    });
}

pub fn handle_file(app: &AppHandle, state: &Arc<AppState>, path: &Path) {
    let started = Instant::now();
    let path_str = path.display().to_string();
    state.set_current_scan(Some(path_str.clone()));
    let _ = app.emit(
        "argus://scan-start",
        serde_json::json!({ "path": path_str }),
    );

    let (det, size) = match scanner::scan_file(path) {
        Ok(Some(d)) => {
            let sz = d.size;
            (Some(d), sz)
        }
        Ok(None) => (None, std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)),
        Err(_) => (None, 0),
    };
    let duration_ms = started.elapsed().as_millis() as u64;

    state.set_current_scan(None);
    state.set_watched_count(state.watch.lock().watched.len());

    if let Some(det) = det {
        react(app, state, det);
    } else {
        let evt = ActivityEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            kind: "scanned".into(),
            path: path_str,
            size,
            duration_ms,
            note: Some("clean".into()),
        };
        state.push_activity(evt.clone());
        let _ = app.emit("argus://activity", evt);
    }
}

fn react(app: &AppHandle, state: &Arc<AppState>, mut det: Detection) {
    tracing::warn!("detection: {} severity={:?}", det.path, det.top_severity);

    let cfg = state.config.lock().clone();
    let mut action = "detected".to_string();
    let mut quarantined = false;

    if cfg.protection_enabled && cfg.auto_kill_processes {
        let mut set = HashSet::new();
        set.insert(det.path.clone());
        let killed = kill_processes_using(&set);
        if !killed.is_empty() {
            action = format!("killed_pids:{}", killed.len());
        }
    }

    if cfg.protection_enabled && cfg.auto_quarantine {
        match quarantine::quarantine(&det) {
            Ok(entry) => {
                action = "quarantined".into();
                quarantined = true;
                let _ = app.emit("argus://quarantine", entry);
            }
            Err(e) => tracing::error!("quarantine failed: {e}"),
        }
    }

    det.action = action.clone();
    state.push_detection(det.clone());

    // Activity log entry. Use kind="quarantined" when we actually moved the
    // file, otherwise "detected" (detect-only mode).
    let evt = ActivityEvent {
        timestamp: det.timestamp.clone(),
        kind: if quarantined { "quarantined".into() } else { "detected".into() },
        path: det.path.clone(),
        size: det.size,
        duration_ms: 0,
        note: Some(format!(
            "{:?} - {} rule match{}",
            det.top_severity,
            det.hits.len(),
            if det.hits.len() == 1 { "" } else { "es" }
        )),
    };
    state.push_activity(evt.clone());
    let _ = app.emit("argus://activity", evt);
    let _ = app.emit("argus://detection", det.clone());

    // Auto-triage with Claude. Gated on the config toggle. We only fire
    // for Medium+ severity so a burst of Low informational rows doesn't
    // spin up dozens of CLI processes.
    if cfg.auto_claude_triage
        && crate::scanner::severity_rank(det.top_severity)
            >= crate::scanner::severity_rank(crate::rules::Severity::Medium)
    {
        let app_c = app.clone();
        let state_c = state.clone();
        std::thread::spawn(move || {
            auto_triage(app_c, state_c, det);
        });
    }
}

fn auto_triage(app: AppHandle, state: Arc<AppState>, det: Detection) {
    let first = det.hits.first().cloned();
    let (line, rule_id, rule_title) = match first {
        Some(h) => (h.line, h.rule_id, h.title),
        None => return,
    };
    let raw = match run_claude_print(&det.path, line, &rule_id, &rule_title) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("auto-triage claude failed: {e}");
            return;
        }
    };
    let verdict = parse_verdict(&raw);
    {
        let mut dets = state.detections.lock();
        if let Some(d) = dets.iter_mut().find(|x| x.id == det.id) {
            d.claude_verdict = Some(verdict.clone());
        }
    }
    // If Claude calls it benign with medium/high confidence, auto-dismiss
    // so the same file+rule never re-alerts.
    let v_low = verdict.verdict.to_ascii_lowercase();
    let c_low = verdict.confidence.to_ascii_lowercase();
    if v_low.starts_with("benign") && (c_low == "high" || c_low == "medium") {
        let rule_ids: std::collections::HashSet<String> =
            det.hits.iter().map(|h| h.rule_id.clone()).collect();
        for r in rule_ids {
            let _ = crate::dismissals::add(
                &det.path,
                &det.sha256,
                &r,
                Some(format!(
                    "auto-dismissed by Claude: {}",
                    verdict.reasoning.chars().take(120).collect::<String>()
                )),
                "claude",
            );
        }
        let mut dets = state.detections.lock();
        dets.retain(|d| d.id != det.id);
    }
    let _ = app.emit(
        "argus://claude-verdict",
        serde_json::json!({
            "detection_id": det.id,
            "verdict": verdict,
        }),
    );
}

fn run_claude_print(path: &str, line: Option<usize>, rule_id: &str, rule_title: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let center = line.unwrap_or(1).max(1);
    let start = center.saturating_sub(30).max(1);
    let end = (center + 30).min(total.max(1));
    let excerpt: String = lines[(start.saturating_sub(1))..end].join("\n");
    let excerpt = if excerpt.len() > 12_000 {
        let mut cut = 12_000;
        while !excerpt.is_char_boundary(cut) && cut > 0 { cut -= 1; }
        format!("{}\n... (truncated)", &excerpt[..cut])
    } else { excerpt };

    let prompt = format!(
        "A supply-chain security scanner flagged this code at `{}` around line {}.\n\n\
         Rule: {} - {}\n\n\
         Is this actually malicious, or a false positive?\n\n\
         Respond exactly as:\n\
         VERDICT: benign|suspicious|malicious\n\
         CONFIDENCE: low|medium|high\n\
         REASONING: 1-3 sentences.\n\n\
         ---\n```\n{}\n```",
        path, center, rule_id, rule_title, excerpt
    );

    let out = std::process::Command::new("claude")
        .args(["--print"])
        .arg(&prompt)
        .output()
        .map_err(|e| format!("claude CLI: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn parse_verdict(raw: &str) -> crate::scanner::ClaudeVerdict {
    let mut verdict = "unknown".to_string();
    let mut confidence = "unknown".to_string();
    let mut reasoning = String::new();
    for line in raw.lines() {
        let low = line.trim().to_ascii_lowercase();
        if let Some(v) = low.strip_prefix("verdict:") {
            verdict = v.trim().to_string();
        } else if let Some(c) = low.strip_prefix("confidence:") {
            confidence = c.trim().to_string();
        } else if let Some(r) = line.trim().strip_prefix("REASONING:") {
            reasoning = r.trim().to_string();
        }
    }
    if reasoning.is_empty() {
        reasoning = raw.chars().take(400).collect();
    }
    crate::scanner::ClaudeVerdict {
        verdict,
        confidence,
        reasoning,
        verified_at: chrono::Utc::now().to_rfc3339(),
        raw: raw.to_string(),
    }
}

pub fn add_path(state: &AppState, path: &Path) -> Result<(), String> {
    let mut mgr = state.watch.lock();
    let w = mgr.watcher.as_mut().ok_or("watcher not initialised")?;
    w.watch(path, RecursiveMode::Recursive)
        .map_err(|e| e.to_string())?;
    mgr.watched.insert(path.to_path_buf());
    Ok(())
}

pub fn remove_path(state: &AppState, path: &Path) -> Result<(), String> {
    let mut mgr = state.watch.lock();
    let w = mgr.watcher.as_mut().ok_or("watcher not initialised")?;
    w.unwatch(path).map_err(|e| e.to_string())?;
    mgr.watched.remove(path);
    Ok(())
}

/// Mutex guard helper - lock-free-ish access isn't needed here.
pub fn watched_paths(state: &AppState) -> Vec<PathBuf> {
    state.watch.lock().watched.iter().cloned().collect()
}

/// Public helper for testing: synchronously scan a path and apply reaction.
pub fn force_check(app: &AppHandle, state: &Arc<AppState>, path: &Path) -> Option<Detection> {
    let det = scanner::scan_file(path).ok().flatten()?;
    let det_clone = det.clone();
    react(app, state, det);
    Some(det_clone)
}

/// Walk a directory and run each file through the normal scan pipeline,
/// emitting activity events. Returns the number of files scanned.
pub fn scan_tree(app: &AppHandle, state: &Arc<AppState>, root: &Path) -> usize {
    let skip = [
        "node_modules", ".git", "target", "dist", "build", ".next",
        ".cache", ".argus",
    ];
    let walker = walkdir::WalkDir::new(root).follow_links(false).into_iter();
    let mut count = 0usize;
    for entry in walker.filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        !skip.iter().any(|s| *s == name.as_ref())
    }) {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if !scanner::candidate_file(p) {
            continue;
        }
        if scanner::is_path_excluded(p) {
            continue;
        }
        handle_file(app, state, p);
        count += 1;
        // Throttle emission to keep the UI responsive on large trees.
        if count % 200 == 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    state.set_watched_count(state.watch.lock().watched.len());
    let _ = app.emit(
        "argus://scan-complete",
        serde_json::json!({ "root": root.display().to_string(), "count": count }),
    );
    count
}

// Make Mutex visible for parking_lot.
pub type WatchMutex = Mutex<WatchManager>;
