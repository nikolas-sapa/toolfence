import { createInterface } from "node:readline";
import { writeFileSync } from "node:fs";

const [mode, output, ...args] = process.argv.slice(2);
if (output && output !== "-") writeFileSync(output, JSON.stringify(args[0] === "--record-pid" ? { pid: process.pid } : args));
const lines = createInterface({ input: process.stdin });
if (mode === "stubborn" || mode === "stubborn-error") {
  process.on("SIGTERM", () => {});
  setInterval(() => {}, 1000);
} else lines.on("close", () => process.exit(0));
lines.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.id === undefined || mode === "hang" || mode === "stubborn") return;
  let result;
  if (request.method === "initialize") {
    result = {
      protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "local-fixture", version: "1" },
    };
  } else if (request.method === "tools/list") {
    if (["error", "stubborn-error", "control-error"].includes(mode)) {
      const message = mode === "control-error" ? "fixture\u001b[2J list failed" : "fixture list failed";
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: request.id, error: { code: -32603, message } }) + "\n");
      return;
    }
    result = mode === "invalid" ? { tools: [{ name: 123 }] } : {
      tools: [{ name: "fixture_tool", inputSchema: { type: "object" } }],
    };
  }
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }) + "\n");
});
