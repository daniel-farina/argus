# Argus

> Real-time supply-chain guard for dev machines. Argus watches the folders you code in and blocks the malware that ships inside `npm install`, fake job interviews, and random "screening tasks" from recruiters you've never met.

Native macOS app built with Tauri 2 + Rust. Detect-only by default so you can review before anything is moved.

<p align="center">
  <img src="src-tauri/icons/icon.png" width="160" alt="Argus icon" />
</p>

## Why this exists

Every few weeks a developer posts the same thread: *a recruiter sent me a take-home task, I cloned the repo, ran `npm install`, and my keychain / SSH keys / MetaMask got emptied*. The "fake interview" vector is real, cheap, and reliably works because:

- npm/yarn/pnpm happily run `preinstall` / `postinstall` / `prepare` scripts the second you type `install`.
- Most devs don't read the `package.json` scripts block of every transitive dep.
- One `curl $EVIL | bash` is all it takes.
- Even if you spot it, the payload is usually a base64'd loader inside an innocuous JS file; you have to know what you're looking at.

Argus sits between you and that: every file written into a folder you've pointed it at gets scanned by a rule engine looking for the patterns those attackers reuse (eval-of-base64 loaders, keychain / SSH / browser-login reads, crypto-wallet exfil paths, `curl | bash` install hooks, reverse shells, AppleScript phish dialogs, known-bad and typosquat dependency names).

If something trips, you get a red row in the UI with the exact matched bytes highlighted, plus a one-click **"Ask Claude"** to get a verdict on whether it's real or a false positive. A **Panic** button drops all outbound TCP via `pfctl` if you want to hard-stop while you investigate.

---

## Install / run locally

Prerequisites:

- macOS (tested on Apple Silicon)
- Rust `1.77+` (`rustup default stable`)
- Node `20+`
- Xcode Command Line Tools
- `tauri-cli`: `cargo install tauri-cli --version '^2'`

```bash
git clone https://github.com/<you>/argus.git
cd argus
npm install          # selenium-webdriver for e2e tests
cd src-tauri && cargo tauri dev
```

Production bundle:

```bash
cd src-tauri && cargo tauri build
# Produces target/release/bundle/macos/Argus.app
```

First launch opens the Overview route. Click **Folders → Add folder** and point it at `~/code` (or wherever you clone repos). Detect-only mode is the default, so nothing gets moved until you flip the toggles in **Settings**. The **Panic** button in the top-right needs a macOS admin prompt the first time.

## Run the tests

```bash
bash scripts/bench.sh          # Rust unit + integration + OSS noise budget
bash scripts/run-all-tests.sh  # everything above + WebDriver e2e on the real app
```

The suite includes:

- **Rule assertions** against a malicious-fixture suite in `~/code/bad-fixtures/` (typosquat, crypto-stealer, reverse-shell interview task, obfuscated loader, keychain exfil, deeply-nested malicious transitive dep). All fixtures are inert - fake IPs, fake hosts, no real network IO - but signature-rich enough to exercise every detector.
- **OSS noise budget**: scans installed `node_modules` of popular OSS (`express`, `chalk`, `lodash`, ...) and asserts total High+ detections stay below a threshold.
- **WebDriver e2e** via [`tauri-webdriver-automation`](https://crates.io/crates/tauri-webdriver-automation) + `selenium-webdriver` - launches the real app, exercises every Tauri command, writes a live fixture, waits for the fs-watcher to fire.

## How it works

Each file write in a monitored folder goes through a two-stage pipeline:

```
  fs watcher -> ScanContext -> [Detectors...] -> [Suppressors...] -> Detection
```

**Detectors** (`src-tauri/src/detectors/`) produce hits:

| Detector | Finds |
|---|---|
| `regex_rules` | Declarative regex rules in `rules.rs` (eval+base64, `curl \| bash`, SSH/keychain/wallet dir reads, reverse shells, AppleScript phish, exfil hosts) |
| `package_json` | Structured script analysis. `husky`/`node-gyp`/`tsc` = benign, `curl \| bash` / `node -e` / base64+eval = Critical |
| `entropy` | High-Shannon single-line quoted blobs (obfuscated loaders) |
| `typosquat` | Levenshtein-1 matches against a curated popular-package list, first-party `package.json` only |

**Suppressors** (`src-tauri/src/suppressors/`) downgrade / drop hits based on file context:

- `declaration.rs` - `.d.ts` type files never run code, drop pattern hits
- `bundle.rs` - single-rule hits in minified bundles get demoted
- `known_good.rs` - allowlist of OSS packages whose source legitimately contains suspicious-looking strings (`acorn`, `eslint`, `uglify-js`, `es-abstract`, `core-js`, ...). Keeps PKG-/TYPO- rules at full severity so supply-chain takeovers still surface.
- `regex_literal.rs` - matches inside `/.../` regex literals are skipped
- `local_ip.rs` - raw IP exfil hits on 127.0.0.1 / RFC1918 / link-local drop; public-IP hits demote

Adding a new detector is one file in `detectors/` plus one line in `registered_detectors()`. Same for suppressors.

State is kept in Rust (`AppState.detections` / `.activity` / `.stats`), persisted config at `~/.argus/config.json`, quarantined files at `~/.argus/quarantine/`.

## Threat model covered

- Malicious `preinstall` / `postinstall` / `install` / `prepare` scripts
- `curl ... | bash`, `wget ... | sh` installers
- Obfuscated loaders: `eval(Buffer.from(...,'base64'))`, `new Function(atob(...))`, hex / unicode blobs
- Credential reads: `~/.ssh/id_*`, `~/.aws/credentials`, `Library/Keychains/login.keychain-db`, Chrome/Brave/Edge/Firefox login DBs
- Crypto wallet scans: MetaMask/Phantom Chrome extension IDs, Exodus / Electrum / Ledger Live / Trezor Suite Application Support dirs
- Reverse shells: `bash -i >& /dev/tcp/...`, `nc -e`, `python -c 'import socket'`
- AppleScript dialog phishing
- Exfil to known hostile hosts (transfer.sh, webhook.site, requestbin, glitch.me, ngrok, duckdns, pastebin)
- Known-bad and typosquat package names

## Contributing

Yes please. The two highest-leverage contributions:

1. **More detectors / rules.** If you've seen a supply-chain pattern in the wild, open a PR adding a rule to `src-tauri/src/rules.rs` (declarative regex) or a new module under `src-tauri/src/detectors/` (structured). Include a fixture under `~/code/bad-fixtures/<yourname>/` and a test in `src-tauri/tests/bench.rs`.
2. **False-positive reports.** Run `cargo run --release --example bench_all` against your own `~/code/test-repos/` clone of popular OSS. If something obviously benign is tripping High+, open an issue with the rule id, file path, and matched text.

Contribution workflow:

```bash
git checkout -b feat/your-thing
# ... make changes ...
bash scripts/bench.sh        # must stay green
git commit -m "feat: ..."
gh pr create
```

Commit style: conventional-commits (`feat(scope):` / `fix(scope):` / `chore:` / `test:` / `docs:`). Keep commits focused per file area (see `git log --oneline` for the pattern).

Ground rules:

- **No false positives without a reason.** Every rule either adds signal or it doesn't ship. A rule that floods a clean `npm install` fails review.
- **No backdoors, no telemetry.** Argus never calls home.
- **Add tests.** New detectors need a positive fixture and (ideally) an OSS negative.

## License

MIT.

## Acknowledgements

Inspired by the Turshija 2026-04-23 fake-interview writeup and by everyone who's lost a wallet to a `postinstall`. Named for Argus Panoptes, the all-seeing mythological guardian.
