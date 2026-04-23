use crate::rules::{Confidence, Severity, BAD_HOSTS};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, Signal, System};

/// Executable path prefixes for apps that legitimately speak to the
/// internet. Everything under here gets Low severity unless the remote
/// is on BAD_HOSTS.
pub static KNOWN_GOOD_APP_PATHS: &[&str] = &[
    "/Applications/Google Chrome.app/",
    "/Applications/Safari.app/",
    "/Applications/Firefox.app/",
    "/Applications/Brave Browser.app/",
    "/Applications/Microsoft Edge.app/",
    "/Applications/Arc.app/",
    "/Applications/Slack.app/",
    "/Applications/Signal.app/",
    "/Applications/Discord.app/",
    "/Applications/Telegram.app/",
    "/Applications/WhatsApp.app/",
    "/Applications/Zoom.us.app/",
    "/Applications/zoom.us.app/",
    "/Applications/Microsoft Teams.app/",
    "/Applications/Spotify.app/",
    "/Applications/Visual Studio Code.app/",
    "/Applications/Cursor.app/",
    "/Applications/Xcode.app/",
    "/Applications/IntelliJ IDEA.app/",
    "/Applications/PyCharm.app/",
    "/Applications/Android Studio.app/",
    "/Applications/Notion.app/",
    "/Applications/Obsidian.app/",
    "/Applications/Raycast.app/",
    "/Applications/1Password 7.app/",
    "/Applications/1Password.app/",
    "/Applications/Docker.app/",
    "/Applications/OrbStack.app/",
    "/Applications/Tailscale.app/",
    "/Applications/Ollama.app/",
    "/Applications/LM Studio.app/",
    "/Applications/Epic Games Launcher.app/",
    "/Applications/Steam.app/",
    "/Applications/Mail.app/",
    "/Applications/Messages.app/",
    "/Applications/Music.app/",
    "/Applications/TV.app/",
    "/Applications/Photos.app/",
    "/Applications/FaceTime.app/",
    "/Applications/Dropbox.app/",
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/bin/",
    "/bin/",
    // Known-good user-local CLIs.
    "/Users/web/.local/bin/claude",
    "/opt/homebrew/bin/",
    "/usr/local/bin/",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub name: String,
    pub cmd: String,
    pub reason: String,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
}

/// Kill any running process whose command line references a path under
/// the provided set of paths. Returns how many were killed.
pub fn kill_processes_using(paths: &HashSet<String>) -> Vec<u32> {
    let mut killed = Vec::new();
    if paths.is_empty() {
        return killed;
    }
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All);
    for (pid, proc_) in sys.processes() {
        let cmd = proc_.cmd().join(std::ffi::OsStr::new(" "));
        let cmd_str = cmd.to_string_lossy().to_string();
        let exe = proc_
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let mut hit = false;
        for p in paths {
            if cmd_str.contains(p) || exe.contains(p) {
                hit = true;
                break;
            }
        }
        if hit {
            let _ = proc_.kill_with(Signal::Kill);
            killed.push(pid.as_u32());
        }
    }
    killed
}

pub fn kill_pid(pid: u32) -> bool {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All);
    if let Some(proc_) = sys.process(Pid::from_u32(pid)) {
        return proc_.kill_with(Signal::Kill).unwrap_or(false);
    }
    false
}

/// List processes whose command line runs inside any monitored folder and
/// appears to be a package-install/build tool (npm, pnpm, yarn, node, python).
pub fn scan_dev_processes(monitored: &[String]) -> Vec<SuspiciousProcess> {
    let mut out = Vec::new();
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All);

    let triggers = ["npm", "pnpm", "yarn", "npx", "node", "python", "python3", "bash", "zsh", "sh"];

    for (pid, proc_) in sys.processes() {
        let name = proc_.name().to_string_lossy().to_string();
        if !triggers.iter().any(|t| name == *t || name.ends_with(t)) {
            continue;
        }
        let cmd = proc_
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let cwd = proc_
            .cwd()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let exe = proc_
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let in_monitored = monitored.iter().any(|m| {
            let mp = Path::new(m);
            let mps = mp.display().to_string();
            cwd.starts_with(&mps) || cmd.contains(&mps) || exe.starts_with(&mps)
        });

        if !in_monitored {
            continue;
        }

        let (sev, conf, reason) = assess_dev_process(&name, &cmd, &exe);

        // Suppress the "regular dev tool in monitored folder" noise at
        // the list level - only surface processes that are actually
        // doing something suspicious. Low stays in the feed as info.
        out.push(SuspiciousProcess {
            pid: pid.as_u32(),
            name,
            cmd,
            reason,
            exe: if exe.is_empty() { None } else { Some(exe) },
            cwd: if cwd.is_empty() { None } else { Some(cwd) },
            severity: sev,
            confidence: conf,
        });
    }
    out
}

fn assess_dev_process(name: &str, cmd: &str, _exe: &str) -> (Severity, Confidence, String) {
    let low = cmd.to_ascii_lowercase();

    // Genuinely suspicious patterns in the command line.
    if low.contains(" | bash") || low.contains(" | sh") || low.contains(" | zsh") {
        return (
            Severity::Critical,
            Confidence::High,
            "pipes to shell in monitored folder".into(),
        );
    }
    if low.contains("curl ") && (low.contains("bash") || low.contains("sh ") || low.contains("| sh")) {
        return (
            Severity::Critical,
            Confidence::High,
            "curl piped to shell".into(),
        );
    }
    if low.contains(" -e ") && (low.contains("eval") || low.contains("buffer.from") || low.contains("atob")) {
        return (
            Severity::Critical,
            Confidence::High,
            "inline eval of decoded payload".into(),
        );
    }
    if low.contains("/dev/tcp/") || low.contains("nc -e ") {
        return (
            Severity::Critical,
            Confidence::High,
            "reverse-shell pattern in cmdline".into(),
        );
    }
    if low.contains("osascript -e") && low.contains("display dialog") {
        return (
            Severity::High,
            Confidence::Medium,
            "AppleScript dialog phishing".into(),
        );
    }
    if name.contains("curl") || name.contains("wget") {
        return (
            Severity::Medium,
            Confidence::Low,
            "network downloader running in monitored folder".into(),
        );
    }
    if low.contains("preinstall") || low.contains("postinstall") {
        return (
            Severity::Medium,
            Confidence::Low,
            "package install hook running".into(),
        );
    }

    // Normal dev tool activity - informational only.
    (
        Severity::Low,
        Confidence::High,
        "dev tool in monitored folder".into(),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetConnection {
    pub pid: u32,
    pub command: String,
    pub remote: String,
    pub bad: bool,
    pub reason: Option<String>,
    pub path: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub severity: Severity,
    pub confidence: Confidence,
    pub first_seen: Option<String>,
    pub is_new: bool,
}

/// Enumerate outbound TCP connections via `lsof -nP -iTCP -sTCP:ESTABLISHED`.
/// Flag any connecting to a hostile host from BAD_HOSTS or raw IP to
/// non-LAN address. Enriches each connection with the owning process's
/// executable path and (where `nettop` is available) per-process byte counts.
pub fn scan_connections() -> Vec<NetConnection> {
    let out = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcPn"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    let text = String::from_utf8_lossy(&out.stdout);

    let mut conns: Vec<NetConnection> = Vec::new();
    let mut cur_pid: u32 = 0;
    let mut cur_cmd = String::new();

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (tag, rest) = line.split_at(1);
        match tag {
            "p" => cur_pid = rest.parse().unwrap_or(0),
            "c" => cur_cmd = rest.to_string(),
            "n" => {
                if let Some(remote) = rest.split("->").nth(1) {
                    let mut conn = NetConnection {
                        pid: cur_pid,
                        command: cur_cmd.clone(),
                        remote: remote.to_string(),
                        bad: false,
                        reason: None,
                        path: None,
                        bytes_in: 0,
                        bytes_out: 0,
                        severity: Severity::Low,
                        confidence: Confidence::Low,
                        first_seen: None,
                        is_new: false,
                    };
                    for h in BAD_HOSTS {
                        if remote.contains(h) {
                            conn.bad = true;
                            conn.reason = Some(format!("connects to hostile host {}", h));
                            break;
                        }
                    }
                    conns.push(conn);
                }
            }
            _ => {}
        }
    }

    // Enrich with process exe path from sysinfo.
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All);
    for conn in conns.iter_mut() {
        if let Some(proc_) = sys.process(Pid::from_u32(conn.pid)) {
            if let Some(exe) = proc_.exe() {
                conn.path = Some(exe.display().to_string());
            }
        }
    }

    // Assess severity per connection.
    for conn in conns.iter_mut() {
        let (sev, conf, reason) = assess_connection(conn);
        conn.severity = sev;
        conn.confidence = conf;
        if conn.reason.is_none() {
            conn.reason = reason;
        }
    }

    // Enrich with per-process bytes from `nettop`. Best-effort.
    let totals = nettop_bytes();
    if !totals.is_empty() {
        for conn in conns.iter_mut() {
            if let Some(&(bi, bo)) = totals.get(&conn.pid) {
                conn.bytes_in = bi;
                conn.bytes_out = bo;
            }
        }
    }

    conns
}

/// Assess risk level for a connection based on remote host, process exe
/// path, and command name. Centralises the judgement that used to live
/// in the frontend (where it over-flagged).
fn assess_connection(c: &NetConnection) -> (Severity, Confidence, Option<String>) {
    // Hostile host is Critical regardless of who initiated it.
    if c.bad {
        return (Severity::Critical, Confidence::High, c.reason.clone());
    }

    // Localhost or RFC1918 - Low, informational.
    if is_local_remote(&c.remote) {
        return (
            Severity::Low,
            Confidence::High,
            Some("local or private-network target".into()),
        );
    }

    // Known-good application -> Low.
    if let Some(p) = &c.path {
        for allow in KNOWN_GOOD_APP_PATHS {
            if p.starts_with(allow) {
                return (
                    Severity::Low,
                    Confidence::High,
                    Some(format!("known-good app: {}", &p[..allow.len().min(p.len())])),
                );
            }
        }
    }

    let lower = c.command.to_ascii_lowercase();

    // Shell interpreters or network CLIs speaking to public IPs - High.
    for s in &["bash", "sh", "zsh", "fish", "nc", "ncat", "curl", "wget", "socat"] {
        if lower == *s {
            return (
                Severity::High,
                Confidence::Medium,
                Some(format!("shell/cli '{}' outbound to public address", s)),
            );
        }
    }

    // Dev runtimes (node, python, ruby, go, ...) reaching public IPs - Medium.
    for r in &["node", "python", "python3", "ruby", "go", "deno", "bun", "tsx"] {
        if lower == *r || lower.starts_with(&format!("{} ", r)) {
            return (
                Severity::Medium,
                Confidence::Low,
                Some(format!("{} runtime outbound", r)),
            );
        }
    }

    // Otherwise unknown command with public outbound - Medium/Low.
    (
        Severity::Medium,
        Confidence::Low,
        Some("unknown process outbound".into()),
    )
}

fn is_local_remote(remote: &str) -> bool {
    let r = remote.to_ascii_lowercase();
    // IPv6 loopback/link-local including bracketed forms.
    if r.starts_with("[::1]") || r.starts_with("::1") {
        return true;
    }
    if r.starts_with("[fe80") || r.starts_with("fe80:") {
        return true;
    }
    if r.starts_with("[fd") || r.starts_with("[fc") {
        return true; // ULA fc00::/7
    }
    if r == "localhost" || r.starts_with("localhost:") {
        return true;
    }
    if r.starts_with("127.") || r.starts_with("0.0.0.0") || r.starts_with("169.254.") {
        return true;
    }
    if r.starts_with("10.") || r.starts_with("192.168.") {
        return true;
    }
    if let Some(rest) = r.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u16>() {
                if (16..=31).contains(&n) {
                    return true;
                }
            }
        }
    }
    false
}

/// Run `nettop` in batch mode to collect per-process totals. Returns a
/// pid -> (bytes_in, bytes_out) map. If nettop is unavailable or output
/// format is unexpected, returns an empty map.
fn nettop_bytes() -> std::collections::HashMap<u32, (u64, u64)> {
    use std::collections::HashMap;
    let out = Command::new("nettop")
        .args([
            "-n",
            "-P",
            "-x",
            "-l",
            "1",
            "-J",
            "bytes_in,bytes_out",
        ])
        .output();
    let mut map: HashMap<u32, (u64, u64)> = HashMap::new();
    let Ok(out) = out else { return map };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        // Rows look like:
        //   06:15:23.1234,node.2345,1024,4096,
        // or without leading time column in -x mode. We scan for the
        // `name.pid` token and the next two numeric fields.
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 3 {
            continue;
        }
        for i in 0..cols.len() - 2 {
            if let Some((_name, pid_str)) = cols[i].rsplit_once('.') {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    let bi = cols[i + 1].trim().parse::<u64>().ok();
                    let bo = cols[i + 2].trim().parse::<u64>().ok();
                    if let (Some(bi), Some(bo)) = (bi, bo) {
                        let entry = map.entry(pid).or_insert((0, 0));
                        entry.0 = entry.0.saturating_add(bi);
                        entry.1 = entry.1.saturating_add(bo);
                        break;
                    }
                }
            }
        }
    }
    map
}
