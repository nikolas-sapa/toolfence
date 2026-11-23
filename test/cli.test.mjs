import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { serve } from "./fixtures/http-server.mjs";

const cli = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const fixture = fileURLToPath(new URL("./fixtures/stdio-server.mjs", import.meta.url));
const preload = fileURLToPath(new URL("./fixtures/check-error.mjs", import.meta.url));
async function run(args, options = {}) {
  const child = spawn(process.execPath, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => stdout += chunk);
  child.stderr.on("data", (chunk) => stderr += chunk);
  const timeout = setTimeout(() => child.kill("SIGKILL"), 5000);
  try {
    const code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    return { code, stdout, stderr };
  } finally { clearTimeout(timeout); }
}

test("CLI forwards every stdio argv exactly, including whitespace and scanner-like flags", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "toolfence-argv-"));
  const output = join(scratch, "argv.json");
  const args = ["one two", "", "--help", "--json", "--bearer", "literal", "x'y\"z"];
  const result = await run([cli, "--no-baseline", "--json", "--stdio", process.execPath, fixture, "ok", output, ...args]);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).toolCount, 1);
  assert.deepEqual(JSON.parse(await readFile(output, "utf8")), args);
});

test("CLI preserves partial report on unexpected check failure, exits 2, writes no baseline", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "toolfence-check-error-"));
  const result = await run(["--import", preload, cli, "--json", "--stdio", process.execPath, fixture, "ok", "-"], {
    env: { ...process.env, TOOLFENCE_TEST_BASELINE_DIR: scratch },
  });
  assert.equal(result.code, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.toolCount, 1);
  assert.ok(report.findings.some((finding) => finding.checkId === "fixture-error" && finding.detail === "fixture check failed"));
  assert.deepEqual(await readdir(scratch), []);
});

test("CLI escapes remote control characters in discovery errors", async () => {
  const result = await run([cli, "--no-baseline", "--stdio", process.execPath, fixture, "control-error", "-"]);
  assert.equal(result.code, 2);
  assert.equal(result.stderr.includes("\u001b"), false);
  assert.ok(result.stderr.includes("\\u001b[2J"));
});

// The stdio fixture's worst finding is low, with info findings present.
test("CLI --fail-on tunes the exit-1 threshold on a low-severity report", async () => {
  const stdio = ["--stdio", process.execPath, fixture, "ok", "-"];
  assert.equal((await run([cli, "--no-baseline", ...stdio])).code, 0);
  assert.equal((await run([cli, "--no-baseline", "--fail-on", "medium", ...stdio])).code, 0);
  assert.equal((await run([cli, "--no-baseline", "--fail-on", "low", ...stdio])).code, 1);
  assert.equal((await run([cli, "--no-baseline", "--fail-on", "info", ...stdio])).code, 1);
});

test("CLI --fail-on keeps exit 1 opt-in for high findings and off disables it", async () => {
  const server = await serve({ mode: "empty" });
  try {
    assert.equal((await run([cli, "--no-baseline", server.url])).code, 1);
    assert.equal((await run([cli, "--no-baseline", "--fail-on", "critical", server.url])).code, 0);
    assert.equal((await run([cli, "--no-baseline", "--fail-on", "off", server.url])).code, 0);
    assert.equal((await run([cli, "--no-baseline", "--fail-on", "high", server.url])).code, 1);
  } finally { await server.close(); }
});

test("CLI --fail-on rejects invalid values before connecting", async () => {
  for (const args of [["--fail-on", "bogus"], ["--fail-on"]]) {
    const result = await run([cli, ...args, "http://127.0.0.1:1/mcp"]);
    assert.equal(result.code, 2);
    assert.ok(result.stderr.includes("invalid --fail-on"), result.stderr);
  }
});
