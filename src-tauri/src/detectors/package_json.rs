// DEVPROTECTOR_SELF_EXCLUDE
//! Structured analysis of package.json. Differentiates benign install
//! hooks (husky, node-gyp rebuild, simple `node ./bin/...`) from hostile
//! ones (curl | bash, node -e "fetch(...)", base64 eval).

use crate::detectors::{Detector, ScanContext};
use crate::rules::{build_hit_raw, Confidence, RuleHit, Severity, BAD_PACKAGES};

pub struct PackageJsonDetector;

impl Detector for PackageJsonDetector {
    fn id(&self) -> &'static str {
        "package_json"
    }

    fn detect(&self, ctx: &ScanContext) -> Vec<RuleHit> {
        if ctx
            .path
            .file_name()
            .and_then(|n| n.to_str())
            != Some("package.json")
        {
            return Vec::new();
        }
        let v: serde_json::Value = match serde_json::from_str(ctx.content) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let mut hits = Vec::new();

        if let Some(scripts) = v.get("scripts").and_then(|s| s.as_object()) {
            for key in ["preinstall", "install", "postinstall", "prepare"] {
                if let Some(cmd) = scripts.get(key).and_then(|c| c.as_str()) {
                    let (sev, conf, title) = classify_install_script(key, cmd);
                    let offset = ctx.content.find(cmd).unwrap_or(0);
                    hits.push(build_hit_raw(
                        format!("PKG-{}", key.to_uppercase()),
                        title,
                        sev,
                        conf,
                        ctx.content,
                        offset,
                        offset + cmd.len(),
                        Some(cmd.to_string()),
                    ));
                }
            }
        }

        for field in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(deps) = v.get(field).and_then(|d| d.as_object()) {
                for name in deps.keys() {
                    if BAD_PACKAGES.contains(&name.as_str()) {
                        let offset = ctx.content.find(name.as_str()).unwrap_or(0);
                        hits.push(build_hit_raw(
                            "PKG-BADDEP".into(),
                            format!("Known-bad package in {}: {}", field, name),
                            Severity::Critical,
                            Confidence::High,
                            ctx.content,
                            offset,
                            offset + name.len(),
                            Some(name.clone()),
                        ));
                    }
                }
            }
        }
        hits
    }
}

fn classify_install_script(key: &str, cmd: &str) -> (Severity, Confidence, String) {
    let low = cmd.to_ascii_lowercase();

    // Heuristics for clearly hostile install hooks.
    let is_curl_pipe_bash = (low.contains("curl") || low.contains("wget"))
        && (low.contains("|") || low.contains("| bash") || low.contains("| sh"));
    let is_node_eval = low.contains("node -e")
        || low.contains("node --eval");
    let is_py_inline = low.contains("python -c") || low.contains("python3 -c");
    let has_base64_eval = (low.contains("buffer.from") || low.contains("atob"))
        && low.contains("eval");
    let has_shell_redirect = low.contains("/dev/tcp/") || low.contains("nc -e");

    if is_curl_pipe_bash || is_node_eval || is_py_inline || has_base64_eval || has_shell_redirect {
        return (
            Severity::Critical,
            Confidence::High,
            format!("package.json {} runs downloader/inline interpreter: {}", key, short(cmd)),
        );
    }

    // Heuristics for known-benign install hooks.
    let benign_tokens = [
        "husky", "is-ci", "patch-package", "node-gyp", "prebuild-install",
        "node-pre-gyp", "tsc", "npm run build", "node ./scripts",
        "echo ", "simple-git-hooks", "lefthook install", "pnpm build",
        "only-allow", "safe-publish-latest", "npmignore", "not-in-publish",
        "pnpm install", "yarn install", "shx ", "del ", "del-cli",
        "rimraf ", "cross-env ", "mkdirp ", "nyc ", "tape ",
        "wireit", "turbo ", "turbo run", "lerna ", "nx ",
        "npm run postinstall --workspaces", "npm run prepare --workspaces",
        "workspaces --if-present",
    ];
    for t in &benign_tokens {
        if low.contains(t) {
            return (
                Severity::Low,
                Confidence::Low,
                format!("package.json {} runs benign tool ({}): {}", key, t, short(cmd)),
            );
        }
    }

    // Otherwise: install hook exists but we can't tell. Medium/low confidence
    // so the UI isn't flooded with High on every husky install.
    (
        Severity::Medium,
        Confidence::Low,
        format!("package.json {} script: {}", key, short(cmd)),
    )
}

fn short(s: &str) -> String {
    if s.len() <= 160 {
        s.to_string()
    } else {
        format!("{}...", &s[..157])
    }
}
