#!/usr/bin/env node
// toolfence — security scanner for MCP servers.

import { writeFile } from "node:fs/promises";
import { connect } from "./connect.js";
import { CHECKS } from "./checks/index.js";
import { loadBaseline, saveBaseline } from "./baseline.js";
import {
  buildReport,
  renderJsonSafe,
  renderMarkdown,
  renderTerminal,
  worstSeverity,
} from "./report.js";
import type { Finding, ScanContext } from "./types.js";

interface Args {
  target?: string;
  stdio: boolean;
  bearer?: string;
  format: "terminal" | "json" | "markdown";
  out?: string;
  baseline: boolean;
  color: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = {
    stdio: false,
    format: "terminal",
    baseline: true,
    color: process.stdout.isTTY ?? false,
    help: false,
  };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "-h":
      case "--help":
        a.help = true;
        break;
      case "--stdio":
        a.stdio = true;
        break;
      case "--bearer":
        a.bearer = argv[++i];
        break;
      case "--json":
        a.format = "json";
        break;
      case "--markdown":
      case "--md":
        a.format = "markdown";
        break;
      case "-o":
      case "--out":
        a.out = argv[++i];
        break;
      case "--no-baseline":
        a.baseline = false;
        break;
      case "--no-color":
        a.color = false;
        break;
      default:
        rest.push(arg);
    }
  }
  // With --stdio, everything non-flag is the command + its args.
  a.target = a.stdio ? rest.join(" ") : rest[0];
  return a;
}

const HELP = `
toolfence — security scanner for MCP servers

USAGE
  toolfence <url>                 Scan a remote MCP server (Streamable HTTP / SSE)
  toolfence --stdio <cmd...>      Scan a local stdio MCP server
  npx toolfence https://example.com/mcp

OPTIONS
  --bearer <token>   Bearer token for authenticated servers
  --json             Emit machine-readable JSON
  --markdown, --md   Emit a Markdown report
  -o, --out <file>   Write the report to a file
  --no-baseline      Don't read/write the drift-detection baseline
  --no-color         Disable ANSI colors
  -h, --help         Show this help

EXIT CODES
  0  no high/critical findings
  1  at least one high or critical finding
  2  scan could not run (connection/usage error)
`;

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (!args.target) {
    process.stdout.write(HELP);
    return 2;
  }

  let result;
  try {
    result = await connect(args.target, {
      stdio: args.stdio,
      bearer: args.bearer,
    });
  } catch (err) {
    process.stderr.write(
      `toolfence: failed to connect to "${args.target}": ${(err as Error).message}\n`,
    );
    return 2;
  }

  try {
    const baseline = args.baseline
      ? await loadBaseline(args.target)
      : undefined;

    const ctx: ScanContext = {
      connection: result.connection,
      tools: result.tools,
      baseline,
    };

    const findings: Finding[] = [];
    for (const check of CHECKS) {
      try {
        findings.push(...(await check.run(ctx)));
      } catch (err) {
        findings.push({
          checkId: check.id,
          severity: "info",
          title: `Check "${check.id}" errored`,
          detail: (err as Error).message,
        });
      }
    }

    if (args.baseline) {
      await saveBaseline(args.target, result.tools);
    }

    const report = buildReport(
      args.target,
      result.connection.transport,
      result.tools.length,
      findings,
      result.connection.serverName,
      result.connection.serverVersion,
    );

    const rendered =
      args.format === "json"
        ? renderJsonSafe(report)
        : args.format === "markdown"
          ? renderMarkdown(report)
          : renderTerminal(report, args.color);

    if (args.out) {
      await writeFile(args.out, rendered);
      process.stdout.write(`toolfence: report written to ${args.out}\n`);
    } else {
      process.stdout.write(rendered + "\n");
    }

    const worst = worstSeverity(report);
    return worst === "critical" || worst === "high" ? 1 : 0;
  } finally {
    await result.close().catch(() => {});
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`toolfence: fatal: ${err?.stack ?? err}\n`);
    process.exit(2);
  });
