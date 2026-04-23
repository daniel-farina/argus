// DEVPROTECTOR_SELF_EXCLUDE
//! Shared detection primitives: the severity ladder, a single hit record
//! produced by every detector, the regex rule set, and curated package
//! name lists used by detectors and suppressors.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub byte_offset: Option<usize>,
    pub matched: Option<String>,
    pub context: Option<String>,
    pub snippet: Option<String>,
}

pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub pattern: Regex,
    pub file_exts: &'static [&'static str],
}

fn re(s: &str) -> Regex {
    Regex::new(s).expect("bad regex")
}

pub static RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    vec![
        Rule {
            id: "JS001",
            title: "eval() of base64 buffer (classic loader)",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)eval\s*\(\s*(?:Buffer\.from|atob)\s*\("#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx"],
        },
        Rule {
            id: "JS002",
            title: "new Function() dynamic code from decoded string",
            severity: Severity::High,
            confidence: Confidence::High,
            pattern: re(r#"new\s+Function\s*\(\s*(?:Buffer\.from|atob)\s*\("#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx"],
        },
        Rule {
            id: "JS003",
            title: "child_process exec with remote fetch (curl|wget piped to sh)",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)(curl|wget)\s+[^\s'"`]*\s*\|\s*(bash|sh|zsh)"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py"],
        },
        Rule {
            id: "JS004",
            title: "Access to SSH private keys",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)(\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/id_ecdsa)\b"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb"],
        },
        Rule {
            id: "JS005",
            title: "Access to macOS Keychain files",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)(Library/Keychains/login\.keychain|login\.keychain-db)"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb", "go", "rs"],
        },
        Rule {
            id: "JS006",
            title: "Access to Chrome/Brave/Edge credential storage",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)(Google/Chrome/Default/Login Data|BraveSoftware/Brave-Browser|Microsoft Edge/Default/Login Data|Mozilla/Firefox/Profiles|Chromium/Default/Login Data)"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb", "go", "rs"],
        },
        Rule {
            id: "JS007",
            title: "Crypto wallet directory scan (MetaMask/Phantom/Exodus/Atomic)",
            severity: Severity::Critical,
            confidence: Confidence::High,
            // Match either a browser extension ID for a known wallet, or a
            // path fragment like "Application Support/MetaMask". Bare words
            // like "Phantom" tripped on PhantomJS comments in lodash.
            pattern: re(r#"(?i)(nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|(?:Application\s+Support|AppData[/\\]Roaming|\.config)[/\\](?:MetaMask|Phantom|Exodus|Electrum|Atomic|Ledger\s+Live|Trezor\s+Suite))"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb", "go", "rs"],
        },
        Rule {
            id: "JS008",
            title: "AWS credentials file access",
            severity: Severity::High,
            confidence: Confidence::Medium,
            pattern: re(r#"(?i)\.aws/credentials|AWS_SECRET_ACCESS_KEY\s*="#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb", "go", "rs"],
        },
        Rule {
            id: "JS009",
            title: "Base64 blob over 400 chars (likely obfuscated payload)",
            severity: Severity::Medium,
            confidence: Confidence::Low,
            pattern: re(r#"["'`][A-Za-z0-9+/=]{400,}["'`]"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx"],
        },
        Rule {
            id: "JS010",
            title: "Hex string blob over 400 chars",
            severity: Severity::Medium,
            confidence: Confidence::Low,
            pattern: re(r#"["'`](?:\\x[0-9a-fA-F]{2}){50,}["'`]"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx"],
        },
        Rule {
            id: "JS011",
            title: "Unicode escape obfuscation",
            severity: Severity::Medium,
            confidence: Confidence::Low,
            pattern: re(r#"(?:\\u00[46][0-9a-f]){20,}"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx"],
        },
        Rule {
            id: "JS012",
            title: "Suspicious exfil POST to raw IP or dyndns",
            severity: Severity::High,
            confidence: Confidence::Low,
            pattern: re(r#"(?i)(https?://(?:\d{1,3}\.){3}\d{1,3}|\.duckdns\.org|\.ngrok\.io|transfer\.sh|pastebin\.com/raw|requestbin|webhook\.site|glitch\.me)"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb", "go", "rs", "json", "yaml", "yml"],
        },
        Rule {
            id: "JS013",
            title: "Reverse shell pattern (nc -e / bash /dev/tcp)",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)(bash\s+-i\s*>&\s*/dev/tcp/|nc\s+-e\s+/bin/|python\s+-c\s+['\"]import\s+socket)"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb", "go", "rs"],
        },
        Rule {
            id: "JS014",
            title: "Child spawn of osascript (macOS AppleScript dialog phish)",
            severity: Severity::High,
            confidence: Confidence::Medium,
            pattern: re(r#"(?i)osascript\s+-e\s+['\"]display\s+dialog"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx", "sh", "bash", "zsh", "py", "rb"],
        },
        Rule {
            id: "JS015",
            title: "Child process spawn of suspicious shell string",
            severity: Severity::High,
            confidence: Confidence::Medium,
            pattern: re(r#"(?i)(child_process\.(exec|spawn)|execSync)\s*\(\s*['"`]\s*(curl|wget|bash\s+-c|sh\s+-c)\b"#),
            file_exts: &["js", "cjs", "mjs", "ts", "tsx", "jsx"],
        },
        Rule {
            id: "PY001",
            title: "Python exec/eval of decoded payload",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?m)^\s*(exec|eval)\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|__import__)"#),
            file_exts: &["py"],
        },
        Rule {
            id: "PY002",
            title: "Python subprocess downloading and executing",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)urllib.*urlopen.*\.read\(\).*(?:exec|subprocess)"#),
            file_exts: &["py"],
        },
        Rule {
            id: "SH001",
            title: "Shell curl-to-bash install",
            severity: Severity::Critical,
            confidence: Confidence::High,
            pattern: re(r#"(?i)curl\s+[^|]*\s*\|\s*(?:sudo\s+)?(?:bash|sh|zsh)"#),
            file_exts: &["sh", "bash", "zsh"],
        },
    ]
});

pub static BAD_PACKAGES: &[&str] = &[
    "eslint-scope-bad",
    "event-stream-bad",
    "flatmap-stream",
    "getcookies",
    "crossenv",
    "cross-env.js",
    "d3.js",
    "fabric-js",
    "ffmepg",
    "mongose",
    "nodecaffe",
    "noblox.js-proxy",
    "rimraff",
    "tensorfloww",
    "webpackk",
    "gruntcli",
    "loadyaml",
];

pub static BAD_HOSTS: &[&str] = &[
    "transfer.sh",
    "requestbin.com",
    "webhook.site",
    "pastebin.com",
    "anonfiles.com",
    "glitch.me",
    "ngrok.io",
    "duckdns.org",
];

/// Popular npm packages - used by the typosquat detector as a reference
/// set. Kept short on purpose; the goal is to cover obvious targets.
pub static POPULAR_PACKAGES: &[&str] = &[
    "react", "react-dom", "lodash", "express", "axios", "typescript",
    "webpack", "babel", "eslint", "prettier", "jest", "mocha", "chai",
    "chalk", "commander", "request", "moment", "uuid", "dotenv",
    "body-parser", "cors", "socket.io", "ws", "redis", "mongoose",
    "sequelize", "pg", "mysql", "sqlite3", "knex", "node-fetch",
    "cross-env", "rimraf", "nodemon", "ts-node", "yargs", "debug",
    "rxjs", "vue", "next", "nuxt", "vite", "esbuild", "rollup",
    "gulp", "grunt", "parcel", "puppeteer", "playwright", "cypress",
    "stylelint", "husky", "lint-staged", "semver", "yaml",
    "tailwindcss", "postcss", "autoprefixer", "svelte", "solid-js",
    "nestjs", "fastify", "koa", "hapi", "passport", "jsonwebtoken",
    "bcrypt", "sharp", "canvas", "image-size", "fs-extra", "glob",
    // Popular React alternatives that are intentionally close-named.
    "preact", "inferno", "mithril", "riot", "alpinejs",
    // Other popular sibling names.
    "underscore", "ramda", "immer", "zustand", "redux", "mobx",
    "matcha", "eclint", "fetch-mock",
    // Database drivers and ORMs. Names like `mysql2` are distance-1 from
    // `mysql` and used to be flagged as typosquats.
    "mysql2", "mssql", "tedious", "mariadb", "oracledb", "better-sqlite3",
    "kysely", "drizzle-orm", "typeorm", "prisma", "sqlite",
    "node-sass", "sass-embedded",
    // Other intentionally-similar legitimate packages.
    "reselect", "reframework", "react-native", "react-scripts",
    "express-jwt", "express-session", "express-validator",
    "axios-retry", "axios-mock-adapter",
    "lodash-es", "lodash.get", "lodash.merge",
    "vue-router", "vuex", "pinia",
    "next-auth", "next-i18next", "next-themes",
    "vite-plugin-react", "vite-plugin-vue",
    "eslint-config-prettier", "eslint-plugin-prettier",
    "jest-environment-jsdom", "jest-environment-node",
    "typescript-eslint", "@typescript-eslint",
    "ts-jest", "ts-loader", "ts-node-dev",
    "webpack-cli", "webpack-dev-server",
    "rollup-plugin-typescript2",
    "ajv", "async", "bluebird",
    // Bigger dev tool / runtime names.
    "tsx", "tsup", "terser", "swc", "esno", "unbuild",
    // Vue ecosystem - vue2 / vue3 variants that trip 1-char distance.
    "vite-plugin-vue2", "vue-template-compiler", "vue-template-es2015-compiler",
    "vue2", "vue3", "@vue",
    // Common test + util libs that used to trip typosquat.
    "nock", "msw", "vitest",
    // Legacy/deprecated but real: people still see these in old codebases.
    "tslint", "tslint-react", "tslint-config-prettier",
    "jasmine", "protractor",
    // Common sibling/variant names that are distance-1 to popular packages.
    "node-sass-utils", "babel-loader",
];

/// Curated allowlist of packages whose legitimate bundled/source code
/// frequently contains strings that trip our pattern rules (JS parsers,
/// linters, minifiers, spec shims). A hit inside these packages gets
/// demoted by the KnownGoodPackageSuppressor; PKG- and TYPO- rules are
/// kept at full severity so supply-chain takeovers still fire.
pub static KNOWN_GOOD_PACKAGES: &[&str] = &[
    "acorn", "acorn-walk", "esprima", "espree", "estraverse", "esquery",
    "eslint", "eslint-plugin-es-x", "eslint-plugin-unicorn",
    "eslint-plugin-import", "eslint-plugin-react", "eslint-utils",
    "eslint-visitor-keys", "@eslint", "@eslint-community",
    "@humanwhocodes",
    "uglify-js", "terser", "terser-webpack-plugin", "@swc", "swc",
    "babel", "@babel", "babel-plugin", "babel-preset",
    "typescript", "ts-node", "ts-jest", "ts-loader",
    "es-abstract", "es-to-primitive", "es-errors", "es-shim-convert-array-by-copy",
    "object.assign", "object-inspect", "is-regex", "is-string", "is-symbol",
    "regexp.prototype.flags", "define-properties", "has-property-descriptors",
    "workerpool", "mocha", "jest", "@jest", "ava", "tap", "vitest",
    "chai", "sinon",
    "webpack", "rollup", "@rollup", "@webpack", "parcel",
    "tslib", "core-js", "core-js-compat", "core-js-pure", "regenerator-runtime",
    "nyc", "istanbul-reports", "istanbul-lib-coverage", "istanbul-lib-instrument",
    "prettier",
    "lodash", "underscore", "ramda", "immer", "immutable",
    "moment", "date-fns", "dayjs", "luxon",
    "rxjs",
    "diff", "diff-match-patch",
    "superagent", "axios", "node-fetch", "got",
    "qs", "querystringify",
    "chokidar", "anymatch", "glob-parent", "micromatch", "picomatch", "fast-glob",
    "minimatch", "glob",
    "yargs", "yargs-parser", "y18n", "commander", "cli-ui", "cliui",
    "colors", "chalk", "kleur", "ansi-styles", "strip-ansi", "supports-color",
    "debug", "log-symbols",
    "semver", "signal-exit", "foreground-child",
    "ajv", "jsonschema",
    "xo",
];

pub fn build_hit(
    rule_id: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    content: &str,
    start: usize,
    end: usize,
) -> RuleHit {
    build_hit_raw(
        rule_id.to_string(),
        title.to_string(),
        severity,
        confidence,
        content,
        start,
        end,
        None,
    )
}

pub fn build_hit_raw(
    rule_id: String,
    title: String,
    severity: Severity,
    confidence: Confidence,
    content: &str,
    start: usize,
    end: usize,
    override_match: Option<String>,
) -> RuleHit {
    let matched_raw: &str = if start < end && end <= content.len() {
        &content[start..end]
    } else {
        ""
    };
    let matched = override_match.unwrap_or_else(|| truncate(matched_raw, 200));

    let ctx_before = 80;
    let ctx_after = 80;
    let ctx_start = content[..start.min(content.len())]
        .char_indices()
        .rev()
        .nth(ctx_before)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let after_window = content
        .get(end..)
        .unwrap_or("")
        .char_indices()
        .nth(ctx_after)
        .map(|(i, _)| end + i)
        .unwrap_or(content.len());
    let pre = sanitize(&content[ctx_start..start.min(content.len())]);
    let post = sanitize(content.get(end..after_window).unwrap_or(""));
    let context = format!("...{pre}>> {} <<{post}...", sanitize(&matched));

    let line = line_for(content, start);
    let column = column_for(content, start);
    let snippet = content
        .lines()
        .nth(line.unwrap_or(1).saturating_sub(1))
        .and_then(|l| {
            if l.len() > 600 {
                None
            } else {
                Some(l.to_string())
            }
        });

    RuleHit {
        rule_id,
        title,
        severity,
        confidence,
        line,
        column,
        byte_offset: Some(start),
        matched: Some(matched),
        context: Some(context),
        snippet,
    }
}

fn line_for(content: &str, offset: usize) -> Option<usize> {
    Some(
        content[..offset.min(content.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1,
    )
}
fn column_for(content: &str, offset: usize) -> Option<usize> {
    let head = &content[..offset.min(content.len())];
    let last_nl = head.rfind('\n').map(|i| i + 1).unwrap_or(0);
    Some(offset.saturating_sub(last_nl) + 1)
}
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    format!("{}... (+{} bytes)", &s[..end], s.len() - end)
}
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else if c.is_control() {
                '.'
            } else {
                c
            }
        })
        .collect()
}
