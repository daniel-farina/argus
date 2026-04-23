pub mod config;
pub mod detectors;
pub mod dismissals;
pub mod processes;
pub mod quarantine;
pub mod rules;
pub mod scanner;
pub mod state;
pub mod suppressors;
pub mod system;
pub mod watcher;

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{Emitter, State};

use crate::processes::{NetConnection, SuspiciousProcess};
use crate::quarantine::QuarantineEntry;
use crate::scanner::Detection;
use crate::state::{ActivityEvent, ActivityStats, AppState};
use crate::system::SystemStats;

type SharedState<'a> = State<'a, Arc<AppState>>;

#[derive(Debug, Serialize)]
struct Status {
    protection_enabled: bool,
    auto_kill_processes: bool,
    auto_quarantine: bool,
    auto_claude_triage: bool,
    folders: Vec<String>,
    detections_total: usize,
    quarantine_total: usize,
}

#[tauri::command]
fn get_status(state: SharedState<'_>) -> Status {
    let cfg = state.config.lock().clone();
    Status {
        protection_enabled: cfg.protection_enabled,
        auto_kill_processes: cfg.auto_kill_processes,
        auto_quarantine: cfg.auto_quarantine,
        auto_claude_triage: cfg.auto_claude_triage,
        folders: cfg.folders.iter().cloned().collect(),
        detections_total: state.detections.lock().len(),
        quarantine_total: quarantine::list().len(),
    }
}

#[tauri::command]
fn set_protection(
    protection_enabled: Option<bool>,
    auto_kill_processes: Option<bool>,
    auto_quarantine: Option<bool>,
    auto_claude_triage: Option<bool>,
    state: SharedState<'_>,
) {
    {
        let mut cfg = state.config.lock();
        if let Some(v) = protection_enabled {
            cfg.protection_enabled = v;
        }
        if let Some(v) = auto_kill_processes {
            cfg.auto_kill_processes = v;
        }
        if let Some(v) = auto_quarantine {
            cfg.auto_quarantine = v;
        }
        if let Some(v) = auto_claude_triage {
            cfg.auto_claude_triage = v;
        }
    }
    state.persist();
}

#[tauri::command]
fn list_folders(state: SharedState<'_>) -> Vec<String> {
    state.config.lock().folders.iter().cloned().collect()
}

#[tauri::command]
fn add_folder(
    path: String,
    app: tauri::AppHandle,
    state: SharedState<'_>,
) -> Result<(), String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err(format!("path does not exist: {}", path));
    }
    if !p.is_dir() {
        return Err("only directories can be monitored".into());
    }
    let canonical = std::fs::canonicalize(&p)
        .map(|c| c.display().to_string())
        .unwrap_or(path.clone());
    {
        let mut cfg = state.config.lock();
        cfg.folders.insert(canonical.clone());
    }
    state.persist();
    watcher::add_path(&state, Path::new(&canonical))?;

    // Kick off an initial walk so the user sees activity immediately
    // without having to touch a file first.
    let shared: Arc<AppState> = (*state).clone();
    let root = canonical.clone();
    std::thread::spawn(move || {
        watcher::scan_tree(&app, &shared, Path::new(&root));
    });

    Ok(())
}

/// Kick off a background walk of `path`. Returns immediately; file-level
/// progress reaches the UI through `argus://activity` events and
/// a final `argus://scan-complete` event.
#[tauri::command]
fn scan_folder_now(
    path: String,
    app: tauri::AppHandle,
    state: SharedState<'_>,
) -> Result<(), String> {
    let p = PathBuf::from(&path);
    if !p.is_dir() {
        return Err("not a directory".into());
    }
    let shared: Arc<AppState> = (*state).clone();
    std::thread::spawn(move || {
        watcher::scan_tree(&app, &shared, &p);
    });
    Ok(())
}

/// Kick off a background walk of every configured folder.
#[tauri::command]
fn scan_all_folders(app: tauri::AppHandle, state: SharedState<'_>) {
    let folders: Vec<String> = state.config.lock().folders.iter().cloned().collect();
    let shared: Arc<AppState> = (*state).clone();
    std::thread::spawn(move || {
        for f in folders {
            watcher::scan_tree(&app, &shared, Path::new(&f));
        }
    });
}

#[tauri::command]
fn quarantine_path(
    path: String,
    app: tauri::AppHandle,
    state: SharedState<'_>,
) -> Result<QuarantineEntry, String> {
    let p = PathBuf::from(&path);
    if !p.is_file() {
        return Err(format!("not a file: {}", path));
    }
    // Build a Detection for this file so the quarantine index has context.
    let det = scanner::scan_file(&p)
        .map_err(|e| e.to_string())?
        .unwrap_or_else(|| {
            // No rule fired, but the user explicitly asked to quarantine.
            // Synthesise a minimal Detection entry.
            let meta = std::fs::metadata(&p).ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let sha = scanner::sha256_of(&p).unwrap_or_default();
            Detection {
                id: format!("manual-{}", chrono::Utc::now().timestamp_millis()),
                path: path.clone(),
                sha256: sha,
                size,
                top_severity: rules::Severity::Info,
                hits: vec![],
                timestamp: chrono::Utc::now().to_rfc3339(),
                action: "manual".into(),
                claude_verdict: None,
            }
        });
    let entry = quarantine::quarantine(&det).map_err(|e| e.to_string())?;
    let _ = app.emit("argus://quarantine", entry.clone());

    // Also log an activity row so the user sees the action land in the feed.
    let evt = ActivityEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        kind: "quarantined".into(),
        path: path.clone(),
        size: entry.size,
        duration_ms: 0,
        note: Some("manual quarantine".into()),
    };
    state.push_activity(evt.clone());
    let _ = app.emit("argus://activity", evt);
    Ok(entry)
}

#[tauri::command]
fn remove_folder(path: String, state: SharedState<'_>) -> Result<(), String> {
    {
        let mut cfg = state.config.lock();
        cfg.folders.remove(&path);
    }
    state.persist();
    let _ = watcher::remove_path(&state, Path::new(&path));
    Ok(())
}

#[tauri::command]
fn list_detections(state: SharedState<'_>) -> Vec<Detection> {
    state.detections.lock().iter().rev().cloned().collect()
}

#[tauri::command]
fn clear_detections(state: SharedState<'_>) {
    state.detections.lock().clear();
    state.activity.lock().clear();
    {
        let mut s = state.stats.lock();
        s.files_scanned = 0;
        s.bytes_scanned = 0;
        s.detections_count = 0;
        s.quarantined_count = 0;
        s.skipped_count = 0;
        s.last_path = None;
        s.last_kind = None;
        s.last_ts = None;
    }
}

#[tauri::command]
fn list_quarantine() -> Vec<QuarantineEntry> {
    quarantine::list()
}

#[tauri::command]
fn restore_quarantine(id: String) -> Result<(), String> {
    quarantine::restore(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_quarantine(id: String) -> Result<(), String> {
    quarantine::delete(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn scan_path(path: String) -> Vec<Detection> {
    let p = PathBuf::from(path);
    if p.is_dir() {
        scanner::scan_directory(&p)
    } else if p.is_file() {
        scanner::scan_file(&p).ok().flatten().into_iter().collect()
    } else {
        Vec::new()
    }
}

#[tauri::command]
fn scan_processes(state: SharedState<'_>) -> Vec<SuspiciousProcess> {
    let folders: Vec<String> = state.config.lock().folders.iter().cloned().collect();
    processes::scan_dev_processes(&folders)
}

#[tauri::command]
fn scan_network() -> Vec<NetConnection> {
    processes::scan_connections()
}

#[tauri::command]
fn kill_pid(pid: u32) -> bool {
    processes::kill_pid(pid)
}

/// Testing hook: force-scan a path and react as if it had been just-written.
#[tauri::command]
fn force_check(path: String, app: tauri::AppHandle, state: SharedState<'_>) -> Option<Detection> {
    let shared: Arc<AppState> = (*state).clone();
    watcher::force_check(&app, &shared, &PathBuf::from(path))
}

#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[derive(Debug, Serialize)]
struct FileWindow {
    path: String,
    excerpt: String,
    start_line: usize,
    end_line: usize,
    highlight_line: Option<usize>,
    total_lines: usize,
    truncated: bool,
}

#[tauri::command]
fn read_file_context(
    path: String,
    line: Option<usize>,
    context_lines: Option<usize>,
) -> Result<FileWindow, String> {
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let center = line.unwrap_or(1).max(1);
    let ctx = context_lines.unwrap_or(25);
    let start = center.saturating_sub(ctx).max(1);
    let end = (center + ctx).min(total.max(1));
    let start_idx = start.saturating_sub(1);
    let end_idx = end.min(lines.len());
    let mut excerpt: String = lines[start_idx..end_idx].join("\n");
    let max_chars = 32_000;
    let truncated = excerpt.len() > max_chars;
    if truncated {
        let mut cut = max_chars;
        while !excerpt.is_char_boundary(cut) && cut > 0 {
            cut -= 1;
        }
        excerpt.truncate(cut);
        excerpt.push_str("\n... (truncated)");
    }
    Ok(FileWindow {
        path,
        excerpt,
        start_line: start,
        end_line: end,
        highlight_line: line,
        total_lines: total,
        truncated,
    })
}

#[tauri::command]
fn claude_available() -> bool {
    std::process::Command::new("sh")
        .args(["-c", "command -v claude >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tauri::command]
async fn analyze_with_claude(
    path: String,
    line: Option<usize>,
    rule_id: String,
    rule_title: String,
) -> Result<String, String> {
    let content = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| e.to_string())?;
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let center = line.unwrap_or(1).max(1);
    let start = center.saturating_sub(30).max(1);
    let end = (center + 30).min(total.max(1));
    let excerpt: String = lines[(start.saturating_sub(1))..end].join("\n");
    let excerpt = if excerpt.len() > 12_000 {
        let mut cut = 12_000;
        while !excerpt.is_char_boundary(cut) && cut > 0 {
            cut -= 1;
        }
        format!("{}\n... (truncated)", &excerpt[..cut])
    } else {
        excerpt
    };

    let prompt = format!(
        "A supply-chain security scanner flagged the following code at `{}` around line {}.\n\n\
         Rule: {} - {}\n\n\
         Decide whether this is actually malicious or a false positive.\n\n\
         Respond in exactly this shape:\n\
         VERDICT: benign|suspicious|malicious\n\
         CONFIDENCE: low|medium|high\n\
         REASONING: 1-3 sentences explaining.\n\n\
         ---\n```\n{}\n```",
        path, center, rule_id, rule_title, excerpt
    );

    let out = tokio::process::Command::new("claude")
        .args(["--print"])
        .arg(&prompt)
        .output()
        .await
        .map_err(|e| format!("claude CLI error ({}) - is claude installed?", e))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(format!(
            "claude exited with {:?}: {}",
            out.status.code(),
            err
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[derive(Debug, Serialize)]
struct PanicStatus {
    paused: bool,
}

#[tauri::command]
async fn panic_status() -> PanicStatus {
    let out = tokio::process::Command::new("pfctl")
        .args(["-a", "argus", "-s", "rules"])
        .output()
        .await;
    let paused = out
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("block drop out"))
        .unwrap_or(false);
    PanicStatus { paused }
}

#[tauri::command]
async fn panic_pause() -> Result<(), String> {
    // Load a pf anchor that drops all outbound; admin prompt via osascript.
    let shell = "echo 'block drop out all' | pfctl -a argus -f - 2>/dev/null && pfctl -E 2>/dev/null; echo ok";
    let apple_script = format!(
        r#"do shell script "{}" with administrator privileges with prompt "Argus needs admin to pause outbound network.""#,
        shell.replace('"', "\\\"")
    );
    let out = tokio::process::Command::new("osascript")
        .args(["-e", &apple_script])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(())
}

/// Parse the "VERDICT: ...\nCONFIDENCE: ...\nREASONING: ..." shape that
/// analyze_with_claude asks Claude to emit. Falls back to raw text if it
/// doesn't match.
fn parse_claude_verdict(raw: &str) -> scanner::ClaudeVerdict {
    let mut verdict = "unknown".to_string();
    let mut confidence = "unknown".to_string();
    let mut reasoning = String::new();
    for line in raw.lines() {
        let lower = line.trim().to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("verdict:") {
            verdict = v.trim().to_string();
        } else if let Some(c) = lower.strip_prefix("confidence:") {
            confidence = c.trim().to_string();
        } else if let Some(r) = line.trim().strip_prefix("REASONING:") {
            reasoning = r.trim().to_string();
        } else if reasoning.is_empty() && !line.trim().is_empty() && !line.starts_with("VERDICT") && !line.starts_with("CONFIDENCE") {
            // keep accumulating free-form text if the lines weren't labelled
            if !reasoning.is_empty() {
                reasoning.push('\n');
            }
            reasoning.push_str(line.trim());
        }
    }
    scanner::ClaudeVerdict {
        verdict,
        confidence,
        reasoning,
        verified_at: chrono::Utc::now().to_rfc3339(),
        raw: raw.to_string(),
    }
}

#[tauri::command]
async fn triage_detection_with_claude(
    detection_id: String,
    app: tauri::AppHandle,
    state: SharedState<'_>,
) -> Result<scanner::ClaudeVerdict, String> {
    // Snapshot the detection we need to triage.
    let det = {
        let d = state.detections.lock();
        d.iter().find(|x| x.id == detection_id).cloned()
    };
    let Some(det) = det else {
        return Err("detection not found".into());
    };
    let first_hit = det.hits.first().cloned();
    let (line, rule_id, rule_title) = match first_hit {
        Some(h) => (h.line, h.rule_id, h.title),
        None => (None, String::new(), String::new()),
    };

    let raw = analyze_with_claude(det.path.clone(), line, rule_id, rule_title).await?;
    let verdict = parse_claude_verdict(&raw);

    // Write back into the detections buffer.
    {
        let mut dets = state.detections.lock();
        if let Some(d) = dets.iter_mut().find(|x| x.id == detection_id) {
            d.claude_verdict = Some(verdict.clone());
        }
    }
    let _ = app.emit(
        "argus://claude-verdict",
        serde_json::json!({
            "detection_id": detection_id,
            "verdict": verdict,
        }),
    );
    Ok(verdict)
}

#[derive(Debug, Serialize)]
struct DismissResult {
    dismissed: Vec<dismissals::Dismissal>,
}

#[tauri::command]
fn dismiss_detection(
    detection_id: String,
    note: Option<String>,
    source: Option<String>,
    state: SharedState<'_>,
) -> Result<DismissResult, String> {
    let snap = {
        let d = state.detections.lock();
        d.iter().find(|x| x.id == detection_id).cloned()
    };
    let Some(det) = snap else {
        return Err("detection not found".into());
    };
    let src = source.unwrap_or_else(|| "user".into());
    let mut out = Vec::new();
    let rule_ids: std::collections::HashSet<String> =
        det.hits.iter().map(|h| h.rule_id.clone()).collect();
    for r in rule_ids {
        let d = dismissals::add(&det.path, &det.sha256, &r, note.clone(), &src)
            .map_err(|e| e.to_string())?;
        out.push(d);
    }
    // Drop this detection from the live buffer too.
    {
        let mut dets = state.detections.lock();
        dets.retain(|d| d.id != detection_id);
    }
    Ok(DismissResult { dismissed: out })
}

#[tauri::command]
fn list_dismissals() -> Vec<dismissals::Dismissal> {
    dismissals::list()
}

#[tauri::command]
fn undo_dismissal(sha256: String, rule_id: String) -> Result<(), String> {
    dismissals::remove(&sha256, &rule_id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn panic_resume() -> Result<(), String> {
    let shell = "pfctl -a argus -F all 2>/dev/null; echo ok";
    let apple_script = format!(
        r#"do shell script "{}" with administrator privileges with prompt "Argus - resume network.""#,
        shell.replace('"', "\\\"")
    );
    let out = tokio::process::Command::new("osascript")
        .args(["-e", &apple_script])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).to_string());
    }
    Ok(())
}

#[tauri::command]
async fn get_system_stats() -> SystemStats {
    tokio::task::spawn_blocking(system::snapshot)
        .await
        .unwrap_or_else(|_| system::SystemStats {
            cpu_global: 0.0,
            cpu_cores: vec![],
            mem_total: 0,
            mem_used: 0,
            mem_free: 0,
            swap_total: 0,
            swap_used: 0,
            load_avg_1m: 0.0,
            load_avg_5m: 0.0,
            load_avg_15m: 0.0,
            disks: vec![],
            uptime_secs: 0,
            hostname: None,
            os: None,
        })
}

#[tauri::command]
fn get_activity_stats(state: SharedState<'_>) -> ActivityStats {
    let mut s = state.stats.lock().clone();
    s.watched_count = state.watch.lock().watched.len();
    s
}

#[tauri::command]
fn list_activity(limit: Option<usize>, state: SharedState<'_>) -> Vec<ActivityEvent> {
    let a = state.activity.lock();
    let cap = limit.unwrap_or(50).min(a.len());
    a.iter().rev().take(cap).cloned().collect()
}

pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let state = AppState::new();

    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init());

    #[cfg(debug_assertions)]
    {
        builder = builder.plugin(tauri_plugin_webdriver_automation::init());
    }

    builder
        .manage(state.clone())
        .setup(move |app| {
            let handle = app.handle().clone();
            let shared: Arc<AppState> = state.clone();
            // Spawn watcher on the main thread so notify backends initialise
            // cleanly on macOS (FSEvents needs the run loop context).
            watcher::spawn(handle.clone(), shared);
            let _ = quarantine::ensure_dirs();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_protection,
            list_folders,
            add_folder,
            remove_folder,
            list_detections,
            list_quarantine,
            restore_quarantine,
            delete_quarantine,
            scan_path,
            scan_processes,
            scan_network,
            kill_pid,
            force_check,
            app_version,
            get_activity_stats,
            list_activity,
            scan_folder_now,
            scan_all_folders,
            quarantine_path,
            get_system_stats,
            clear_detections,
            read_file_context,
            claude_available,
            analyze_with_claude,
            panic_status,
            panic_pause,
            panic_resume,
            triage_detection_with_claude,
            dismiss_detection,
            list_dismissals,
            undo_dismissal,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
