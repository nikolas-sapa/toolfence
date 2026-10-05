import { test } from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "../dist/connect.js";
import { serve } from "./fixtures/http-server.mjs";

const stdioFixture = fileURLToPath(new URL("./fixtures/stdio-server.mjs", import.meta.url));

test("HTTP catalog includes every page, exactly two list requests", async () => {
  const server = await serve();
  try {
    const result = await connect(server.url);
    try {
      assert.deepEqual(result.tools.map((tool) => tool.name), ["first_tool", "second_tool"]);
      assert.equal(server.requests.filter((request) => request.rpc?.method === "tools/list").length, 2);
    } finally { await result.close(); }
  } finally { await server.close(); }
});

test("legacy SSE fallback completes handshake and pagination, closes stream", async () => {
  const server = await serve({ mode: "sse" });
  try {
    const result = await connect(server.url, { timeoutMs: 1000 });
    assert.deepEqual(result.tools.map((tool) => tool.name), ["first_tool", "second_tool"]);
    await result.close();
    await delay(100);
    assert.equal(server.activeResponses.size, 0);
    assert.equal(server.requests.filter((request) => request.method === "POST" && request.url === "/mcp").length, 1);
  } finally { await server.close(); }
});

test("valid empty catalog remains a successful scan", async () => {
  const server = await serve({ mode: "empty" });
  try {
    const result = await connect(server.url, { timeoutMs: 1000 });
    try { assert.deepEqual(result.tools, []); }
    finally { await result.close(); }
  } finally { await server.close(); }
});

for (const timeoutMs of [0, -1, NaN, Infinity]) {
  test(`invalid timeout ${timeoutMs} fails before any network operation`, async () => {
    const server = await serve();
    try {
      await assert.rejects(connect(server.url, { timeoutMs }), /positive finite/);
      assert.equal(server.requests.length, 0);
    } finally { await server.close(); }
  });
}

for (const mode of ["error", "invalid", "cycle"]) {
  test(`HTTP ${mode} catalog fails closed and closes active transport sockets`, async () => {
    const server = await serve({ mode });
    try {
      await assert.rejects(connect(server.url, { timeoutMs: 500 }));
      await delay(100);
      assert.equal(server.activeResponses.size, 0, "no active response after catalog failure");
      const before = server.requests.length;
      await delay(100);
      assert.equal(server.requests.length, before, "no fallback or further requests after catalog failure");
      if (mode === "cycle") assert.equal(server.requests.filter((request) => request.rpc?.method === "tools/list").length, 2);
    } finally { await server.close(); }
  });
}

for (const mode of ["probe-hang", "init-hang", "sse-hang", "list-hang"]) {
  test(`whole deadline cancels ${mode} under 1200ms, no further requests`, { timeout: 3000 }, async () => {
    const server = await serve({ mode });
    try {
      const started = performance.now();
      await assert.rejects(connect(server.url, { timeoutMs: 200 }), /timed out|timeout/i);
      assert.ok(performance.now() - started < 1200);
      await delay(100);
      const before = server.requests.length;
      await delay(200);
      assert.equal(server.requests.length, before);
      // Global fetch owns the idle keepalive pool. Only active transport
      // requests must close, including the socket carrying the stalled body.
      assert.equal(server.activeResponses.size, 0, "all hanging transport responses closed");
    } finally { await server.close(); }
  });
}

test("deadline covers cumulative probe, initialize and paginated list time", async () => {
  const server = await serve({ delay: 90 });
  try { await assert.rejects(connect(server.url, { timeoutMs: 200 }), /timed out|timeout/i); }
  finally { await server.close(); }
});

for (const mode of ["error", "invalid"]) {
  test(`stdio ${mode} catalog fails instead of returning empty success`, async () => {
    const scratch = await mkdtemp(join(tmpdir(), "toolfence-stdio-"));
    const output = join(scratch, "pid.json");
    await assert.rejects(connect("fixture", { stdioArgs: [process.execPath, stdioFixture, mode, output, "--record-pid"], timeoutMs: 500 }));
    const { pid } = JSON.parse(await readFile(output, "utf8"));
    assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  });
}

test("stdio initialize timeout closes child process", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "toolfence-stdio-"));
  const output = join(scratch, "pid.json");
  const started = performance.now();
  await assert.rejects(connect("fixture", { stdioArgs: [process.execPath, stdioFixture, "hang", output, "--record-pid"], timeoutMs: 600 }), /timed out|timeout/i);
  assert.ok(performance.now() - started < 1200);
  const { pid } = JSON.parse(await readFile(output, "utf8"));
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
});

test("deadline terminates owned child ignoring stdin and SIGTERM under 1200ms", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "toolfence-stdio-"));
  const output = join(scratch, "pid.json");
  const started = performance.now();
  await assert.rejects(connect("fixture", { stdioArgs: [process.execPath, stdioFixture, "stubborn", output, "--record-pid"], timeoutMs: 600 }), /timed out|timeout/i);
  assert.ok(performance.now() - started < 1200);
  const { pid } = JSON.parse(await readFile(output, "utf8"));
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
});

test("deadline bounds cleanup after catalog failure from stubborn child under 1200ms", async () => {
  const scratch = await mkdtemp(join(tmpdir(), "toolfence-stdio-"));
  const output = join(scratch, "pid.json");
  const started = performance.now();
  await assert.rejects(connect("fixture", { stdioArgs: [process.execPath, stdioFixture, "stubborn-error", output, "--record-pid"], timeoutMs: 600 }), /failed|timeout/i);
  assert.ok(performance.now() - started < 1200);
  const { pid } = JSON.parse(await readFile(output, "utf8"));
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
});

test("header probe stops after five seconds and handshake uses remaining deadline", { timeout: 8000 }, async () => {
  const server = await serve({ mode: "probe-hang" });
  try {
    const started = performance.now();
    const result = await connect(server.url, { timeoutMs: 6500 });
    try {
      assert.ok(performance.now() - started >= 4900);
      assert.ok(performance.now() - started < 6500);
      assert.equal(result.tools.length, 2);
      assert.equal(result.connection.httpHeaders, undefined);
    } finally { await result.close(); }
  } finally { await server.close(); }
});
