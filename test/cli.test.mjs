import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

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
