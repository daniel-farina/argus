//! Benchmark suite for Argus's detection pipeline.
//!
//! Two halves:
//!   1. Malicious fixture verification - every fixture under ~/code/bad-fixtures
//!      must be detected with the expected rule and at High or Critical severity.
//!   2. OSS noise budget - optional, gated on env var. Scans real installed
//!      node_modules trees and prints detection counts so we can track drift.

use std::path::PathBuf;

use argus_lib::rules::{RuleHit, Severity};
use argus_lib::scanner::{scan_directory, scan_file, severity_rank};

fn fixtures_root() -> PathBuf {
    dirs::home_dir().unwrap().join("code").join("bad-fixtures")
}

fn is_high_or_critical(hits: &[RuleHit]) -> bool {
    hits.iter()
        .any(|h| severity_rank(h.severity) >= severity_rank(Severity::High))
}

fn has_rule(hits: &[RuleHit], rule_id: &str) -> bool {
    hits.iter().any(|h| h.rule_id == rule_id)
}

fn any_rule_starts(hits: &[RuleHit], prefix: &str) -> bool {
    hits.iter().any(|h| h.rule_id.starts_with(prefix))
}

/* ---------------- fixture tests ---------------- */

#[test]
fn typosquat_fixture_detected() {
    let p = fixtures_root().join("typosquat/package.json");
    let det = scan_file(&p).unwrap().expect("typosquat package.json should detect");
    assert!(
        any_rule_starts(&det.hits, "TYPO"),
        "expected a TYPO- rule to fire, got {:?}",
        det.hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
    assert!(
        is_high_or_critical(&det.hits),
        "expected High or Critical, got {:?}",
        det.top_severity
    );
}

#[test]
fn crypto_stealer_fixture_detected() {
    let p = fixtures_root().join("crypto-stealer/scan.js");
    let det = scan_file(&p).unwrap().expect("crypto stealer should detect");
    // Wallet rule (JS007) or Chrome rule (JS006) or Keychain rule (JS005).
    assert!(
        has_rule(&det.hits, "JS007")
            || has_rule(&det.hits, "JS006")
            || has_rule(&det.hits, "JS005"),
        "expected JS005/JS006/JS007, got {:?}",
        det.hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
    assert_eq!(det.top_severity, Severity::Critical);
}

#[test]
fn crypto_stealer_pkg_install_flagged() {
    let p = fixtures_root().join("crypto-stealer/package.json");
    let det = scan_file(&p).unwrap().expect("crypto stealer package.json should detect");
    assert!(any_rule_starts(&det.hits, "PKG-"));
}

#[test]
fn reverse_shell_fixture_detected() {
    let p = fixtures_root().join("reverse-shell-task/index.js");
    let det = scan_file(&p).unwrap().expect("reverse shell should detect");
    assert!(
        has_rule(&det.hits, "JS013"),
        "expected JS013 reverse shell rule"
    );
    assert_eq!(det.top_severity, Severity::Critical);
}

#[test]
fn reverse_shell_package_json_critical() {
    let p = fixtures_root().join("reverse-shell-task/package.json");
    let det = scan_file(&p).unwrap().expect("reverse shell package.json should detect");
    assert_eq!(
        det.top_severity,
        Severity::Critical,
        "curl|bash postinstall must be Critical, got hits: {:?}",
        det.hits
    );
}

#[test]
fn obfuscated_loader_detected() {
    let p = fixtures_root().join("obfuscated-loader/loader.js");
    let det = scan_file(&p).unwrap().expect("obfuscated loader should detect");
    // Either JS001 (eval+base64) or ENT001 entropy or JS002 new Function+atob.
    assert!(
        has_rule(&det.hits, "JS001") || has_rule(&det.hits, "JS002") || has_rule(&det.hits, "ENT001"),
        "expected JS001/JS002/ENT001 on loader, got {:?}",
        det.hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn keychain_exfil_fixture_detected() {
    let p = fixtures_root().join("keychain-exfil/grab.js");
    let det = scan_file(&p).unwrap().expect("keychain exfil should detect");
    assert!(
        has_rule(&det.hits, "JS005") || has_rule(&det.hits, "JS004") || has_rule(&det.hits, "JS008"),
        "expected a credential-theft rule on grab.js, got {:?}",
        det.hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
    assert_eq!(det.top_severity, Severity::Critical);
}

#[test]
fn deep_nested_malicious_detected() {
    let pkg = fixtures_root().join("deep-nested-malicious/node_modules/requset/package.json");
    let idx = fixtures_root().join("deep-nested-malicious/node_modules/requset/index.js");

    let pkg_det = scan_file(&pkg).unwrap().expect("nested package.json should detect");
    assert_eq!(pkg_det.top_severity, Severity::Critical);

    let idx_det = scan_file(&idx).unwrap().expect("nested index.js should detect");
    assert!(
        has_rule(&idx_det.hits, "JS001")
            || has_rule(&idx_det.hits, "JS004")
            || has_rule(&idx_det.hits, "ENT001"),
        "got {:?}",
        idx_det.hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn every_fixture_dir_has_at_least_one_detection() {
    // `scan_directory` skips node_modules intentionally (to keep "Scan all"
    // quiet on real projects). The deep-nested fixture lives inside
    // node_modules, so for that one we scan its specific files directly,
    // which matches the watcher-triggered code path.
    let cases: &[(&str, &[&str])] = &[
        ("typosquat", &[]),
        ("crypto-stealer", &[]),
        ("reverse-shell-task", &[]),
        ("obfuscated-loader", &[]),
        ("keychain-exfil", &[]),
        (
            "deep-nested-malicious",
            &[
                "node_modules/requset/index.js",
                "node_modules/requset/package.json",
            ],
        ),
    ];
    for (name, extra) in cases {
        let d = fixtures_root().join(name);
        assert!(d.exists(), "missing fixture dir: {:?}", d);
        let mut dets = scan_directory(&d);
        for e in *extra {
            if let Ok(Some(det)) = scan_file(&d.join(e)) {
                dets.push(det);
            }
        }
        assert!(
            !dets.is_empty(),
            "fixture dir {} produced no detections",
            name
        );
    }
}

/* ---------------- clean-input sanity tests ---------------- */

#[test]
fn clean_first_party_code_is_quiet() {
    let tmp = std::env::temp_dir().join("argus-clean-app.js");
    std::fs::write(
        &tmp,
        "export function hello(name) { return `Hello, ${name}!`; }\n\
         export const PI = 3.14159;\n",
    )
    .unwrap();
    let det = scan_file(&tmp).unwrap();
    assert!(det.is_none(), "clean code should not trip any rule");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn eslint_rule_file_is_suppressed_as_known_good() {
    // Simulate a file path inside node_modules/eslint/lib/rules/ that contains
    // the string `eval(atob(...))`. The KnownGoodPackageSuppressor should
    // demote the Critical code-pattern hit.
    let tmp = std::env::temp_dir().join("fake-eslint");
    let sub = tmp.join("node_modules").join("eslint").join("lib").join("rules");
    std::fs::create_dir_all(&sub).unwrap();
    let f = sub.join("no-eval.js");
    std::fs::write(
        &f,
        "// ESLint rule that forbids eval(atob(...)). \n\
         module.exports = { create() { /* detects eval(atob(x)) and eval(Buffer.from(x,'base64')) */ } };\n",
    ).unwrap();
    let det = scan_file(&f).unwrap();
    if let Some(d) = det {
        assert_ne!(
            d.top_severity,
            Severity::Critical,
            "eslint rule file should not surface Critical hit: {:?}",
            d.hits
        );
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn declaration_file_is_suppressed() {
    let tmp = std::env::temp_dir().join("argus-types.d.ts");
    std::fs::write(
        &tmp,
        "export declare function eval(code: string): any;\n\
         export declare function fetch(url: string): Promise<Response>;\n\
         // Types file - mentions eval(atob(...)) in doc but has no runtime code.\n",
    )
    .unwrap();
    let det = scan_file(&tmp).unwrap();
    assert!(
        det.is_none() || det.unwrap().hits.is_empty(),
        ".d.ts declaration files should not trip code-pattern rules"
    );
    let _ = std::fs::remove_file(&tmp);
}

/* ---------------- OSS noise budget (opt-in) ---------------- */

#[test]
fn oss_noise_budget_if_available() {
    if std::env::var("DEVPROTECTOR_BENCH_OSS").is_err() {
        eprintln!("skipping OSS noise benchmark (set DEVPROTECTOR_BENCH_OSS=1 to run)");
        return;
    }
    let repos = [
        ("express", 10),
        ("chalk", 10),
        ("lodash", 5),
    ];
    let mut fail = false;
    for (name, budget) in repos {
        let dir = dirs::home_dir().unwrap().join("code/test-repos").join(name);
        if !dir.exists() {
            eprintln!("SKIP {name}: no cloned repo at {dir:?}");
            continue;
        }
        let dets = scan_directory(&dir);
        let high_plus: Vec<_> = dets
            .iter()
            .filter(|d| severity_rank(d.top_severity) >= severity_rank(Severity::High))
            .collect();
        eprintln!(
            "OSS {:>8}: total={:4}  high+={:4}  (budget {})",
            name, dets.len(), high_plus.len(), budget
        );
        if high_plus.len() > budget {
            fail = true;
        }
    }
    assert!(!fail, "OSS noise exceeded budget");
}
