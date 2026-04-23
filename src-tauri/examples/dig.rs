// ARGUS_SELF_EXCLUDE
use argus_lib::rules::Severity;
use argus_lib::scanner::{scan_directory, severity_rank};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let min_sev = args.first().map(|s| s.as_str()).unwrap_or("High");
    let repo = args.get(1).cloned().unwrap_or_else(|| "next.js".into());
    let root = dirs::home_dir().unwrap().join("code/test-repos").join(&repo);

    let floor = match min_sev {
        "Critical" => Severity::Critical,
        "High" => Severity::High,
        "Medium" => Severity::Medium,
        "Low" => Severity::Low,
        _ => Severity::Info,
    };

    let dets = scan_directory(&root);
    for d in dets {
        if severity_rank(d.top_severity) < severity_rank(floor) {
            continue;
        }
        println!("{:?}  {}", d.top_severity, d.path.replace(&root.display().to_string(), "..."));
        for h in &d.hits {
            if severity_rank(h.severity) < severity_rank(floor) {
                continue;
            }
            println!(
                "  - {} {:?}/{:?} {} :: matched={:?}",
                h.rule_id,
                h.severity,
                h.confidence,
                h.title,
                h.matched.as_deref().unwrap_or("")
            );
        }
        println!();
    }
    let _ = root;
    let _: PathBuf = PathBuf::new();
}
