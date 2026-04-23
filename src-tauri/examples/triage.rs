// ARGUS_SELF_EXCLUDE
//! Scans every repo under ~/code/test-repos and reports High+ findings
//! grouped by (rule_id, matched) for quick FP triage.

use argus_lib::rules::Severity;
use argus_lib::scanner::{scan_directory, severity_rank};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn main() {
    let min_sev = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "High".to_string());
    let floor = match min_sev.as_str() {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Info,
    };
    let root = dirs::home_dir().unwrap().join("code/test-repos");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    dirs.sort();

    // (rule_id, matched-truncated) -> Vec<(repo, path)>
    let mut groups: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    let mut repo_totals: BTreeMap<String, (usize, usize, usize, usize, usize)> = BTreeMap::new(); // total, crit, high, med, low
    let mut scanned = 0usize;

    for d in &dirs {
        let name = d.file_name().unwrap().to_string_lossy().to_string();
        let dets = scan_directory(d);
        scanned += 1;
        let mut totals = (0usize, 0usize, 0usize, 0usize, 0usize);
        for det in dets {
            totals.0 += 1;
            match severity_rank(det.top_severity) {
                4 => totals.1 += 1,
                3 => totals.2 += 1,
                2 => totals.3 += 1,
                1 => totals.4 += 1,
                _ => {}
            }
            if severity_rank(det.top_severity) < severity_rank(floor) {
                continue;
            }
            for h in det.hits {
                if severity_rank(h.severity) < severity_rank(floor) {
                    continue;
                }
                let m = h
                    .matched
                    .unwrap_or_default()
                    .chars()
                    .take(80)
                    .collect::<String>()
                    .replace('\n', " ");
                groups
                    .entry((h.rule_id.clone(), m))
                    .or_default()
                    .push((name.clone(), det.path.clone()));
            }
        }
        repo_totals.insert(name, totals);
    }

    println!("Scanned {} repos", scanned);
    println!("{:<20}  total  crit  high   med   low", "repo");
    println!("{}", "-".repeat(62));
    for (name, (t, c, h, m, l)) in &repo_totals {
        println!("{:<20}  {:>5}  {:>4}  {:>4}  {:>4}  {:>4}", name, t, c, h, m, l);
    }

    println!("\n== High+ groups (rule_id | matched | count | sample files) ==");
    let mut sorted: Vec<_> = groups.iter().collect();
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    for ((rule, matched), files) in sorted {
        println!("\n[{}]  {}x  matched: {:?}", rule, files.len(), matched);
        for (repo, path) in files.iter().take(5) {
            let short = path.split("test-repos/").nth(1).unwrap_or(path);
            println!("    {}  {}", repo, short);
        }
    }
}
