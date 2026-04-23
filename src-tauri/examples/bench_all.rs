// DEVPROTECTOR_SELF_EXCLUDE
//! Quick benchmark: scan every cloned repo under ~/code/test-repos and
//! report detection counts per severity. Fast because it uses
//! scan_directory's default skip list (node_modules, dist, build).

use devprotector_lib::rules::Severity;
use devprotector_lib::scanner::{scan_directory, severity_rank};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let root = dirs::home_dir().unwrap().join("code/test-repos");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    dirs.sort();

    println!(
        "{:<16}  {:>7}  {:>4}  {:>4}  {:>4}  {:>4}  {:>4}   {}",
        "repo", "total", "crit", "high", "med", "low", "ms", "top rules"
    );
    println!("{}", "-".repeat(96));
    for d in &dirs {
        let name = d.file_name().unwrap().to_string_lossy();
        let started = Instant::now();
        let dets = scan_directory(d);
        let ms = started.elapsed().as_millis();
        let mut counts = [0usize; 5];
        let mut rule_counts = std::collections::HashMap::<String, usize>::new();
        for dt in &dets {
            let r = severity_rank(dt.top_severity) as usize;
            counts[r] += 1;
            for h in &dt.hits {
                *rule_counts.entry(h.rule_id.clone()).or_default() += 1;
            }
        }
        let mut top_rules: Vec<_> = rule_counts.iter().collect();
        top_rules.sort_by(|a, b| b.1.cmp(a.1));
        let top_str = top_rules
            .iter()
            .take(3)
            .map(|(k, v)| format!("{}x{}", k, v))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "{:<16}  {:>7}  {:>4}  {:>4}  {:>4}  {:>4}  {:>4}   {}",
            name,
            dets.len(),
            counts[severity_rank(Severity::Critical) as usize],
            counts[severity_rank(Severity::High) as usize],
            counts[severity_rank(Severity::Medium) as usize],
            counts[severity_rank(Severity::Low) as usize],
            ms,
            top_str,
        );
    }
}
