use std::fs;
use std::path::PathBuf;

use argus_lib::rules::Severity;
use argus_lib::scanner::{scan_directory, scan_file, top_severity};

fn fixture_dir() -> PathBuf {
    dirs::home_dir().unwrap().join("code").join("bad")
}

#[test]
fn bad_fixture_exists() {
    let d = fixture_dir();
    assert!(d.exists(), "expected ~/code/bad fixture to exist");
    assert!(d.join("package.json").exists());
    assert!(d.join("scripts/setup.js").exists());
}

#[test]
fn scans_package_json_postinstall_curl_as_critical() {
    let p = fixture_dir().join("package.json");
    let det = scan_file(&p).unwrap().expect("package.json should produce a detection");
    let top = top_severity(&det.hits);
    assert!(
        matches!(top, Severity::Critical | Severity::High),
        "expected Critical/High severity on fixture package.json, got {:?}",
        top
    );
    // At least one rule should mention an install script.
    let has_install_hit = det
        .hits
        .iter()
        .any(|h| h.title.to_lowercase().contains("install") || h.rule_id.starts_with("PKG"));
    assert!(has_install_hit, "expected a package.json install-script rule to fire: {:?}", det.hits);
}

#[test]
fn scans_setup_js_eval_base64_as_critical() {
    let p = fixture_dir().join("scripts/setup.js");
    let det = scan_file(&p).unwrap().expect("setup.js should produce a detection");
    let top = top_severity(&det.hits);
    assert_eq!(
        top as u8, Severity::Critical as u8,
        "setup.js should trip a Critical rule (eval(base64), SSH access, keychain), got {:?} in {:?}",
        top, det.hits
    );
}

#[test]
fn scans_index_js_reverse_shell_and_phish() {
    let p = fixture_dir().join("index.js");
    let det = scan_file(&p).unwrap().expect("index.js should produce a detection");
    // Expect at least the reverse-shell rule JS013.
    let rids: Vec<&str> = det.hits.iter().map(|h| h.rule_id.as_str()).collect();
    assert!(
        rids.iter().any(|r| *r == "JS013"),
        "expected reverse-shell rule JS013 on index.js, got {:?}",
        rids
    );
}

#[test]
fn directory_scan_flags_multiple_files() {
    let d = fixture_dir();
    let dets = scan_directory(&d);
    assert!(
        dets.len() >= 2,
        "expected at least 2 detections in fixture, got {}: {:?}",
        dets.len(),
        dets.iter().map(|d| &d.path).collect::<Vec<_>>()
    );
}

#[test]
fn clean_file_is_not_flagged() {
    let tmp = std::env::temp_dir().join("argus-clean.js");
    fs::write(&tmp, "export function greet() { return 'hello'; }\n").unwrap();
    let det = scan_file(&tmp).unwrap();
    assert!(det.is_none(), "clean file should not produce a detection");
    let _ = fs::remove_file(&tmp);
}

#[test]
fn clean_package_json_is_not_flagged() {
    let tmp = std::env::temp_dir().join("argus-clean-package.json");
    fs::write(
        &tmp,
        r#"{"name":"x","version":"1.0.0","scripts":{"build":"tsc"},"dependencies":{"react":"^18"}}"#,
    )
    .unwrap();
    let det = scan_file(&tmp).unwrap();
    assert!(det.is_none(), "clean package.json should not be flagged: {:?}", det);
    let _ = fs::remove_file(&tmp);
}

#[test]
fn detects_host_indicators_in_json_files() {
    let tmp = std::env::temp_dir().join("argus-exfil.json");
    fs::write(
        &tmp,
        r#"{"remote":"https://requestbin.com/r/abcd","note":"legit","raw_ip":"http://1.2.3.4/exfil"}"#,
    )
    .unwrap();
    let det = scan_file(&tmp).unwrap();
    assert!(det.is_some(), "expected JS012 to fire on exfil host indicators in json");
    let _ = fs::remove_file(&tmp);
}
