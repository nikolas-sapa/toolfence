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
  terminalText,
  worstSeverity,
} from "./report.js";
import { SEVERITY_ORDER } from "./types.js";
import type { Finding, ScanContext, Severity } from "./types.js";

interface Args {
  target?: string;
  stdio: boolean;
  stdioArgs?: string[];
  bearer?: string;
  format: "terminal" | "json" | "markdown";
  out?: string;
  baseline: boolean;
  color: boolean;
  help: boolean;
  failOn: Severity | "off";
  argError?: string;
}

const FAIL_ON_VALUES = [...SEVERITY_ORDER, "off"] as const;

function parseArgs(argv: string[]): Args {
  const a: Args = {
    stdio: false,
    format: "terminal",
    baseline: true,
    color: process.stdout.isTTY ?? false,
    help: false,
    failOn: "high",
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
        a.stdioArgs = argv.slice(i + 1);
        // Preserve the original token boundaries for transport startup and
        // include all arguments in the baseline/report identity.
        a.target = a.stdioArgs.map((part) => JSON.stringify(part)).join(" ");
        return a;
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
      case "--fail-on": {
        const value = argv[++i];
        if ((FAIL_ON_VALUES as readonly string[]).includes(value)) {
          a.failOn = value as Args["failOn"];
        } else {
          a.argError = `invalid --fail-on value "${value ?? "(missing)"}" (expected ${FAIL_ON_VALUES.join("|")})`;
        }
        break;
      }
      default:
        rest.push(arg);
    }
  }
  a.target = rest[0];
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
  --fail-on <sev>    Exit 1 when the worst finding reaches this severity
                     (critical|high|medium|low|info, or off; default: high)
  -h, --help         Show this help

Place scanner options before --stdio. Every argument after --stdio is passed
unchanged to the server, including --help and other option-looking arguments.

EXIT CODES
  0  no finding at or above the --fail-on severity
  1  a finding at or above the --fail-on severity (default: high)
  2  scan could not run (connection/usage error)
`;

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (args.argError) {
    process.stderr.write(`toolfence: ${args.argError}\n`);
    return 2;
  }
  if (!args.target) {
    process.stdout.write(HELP);
    return 2;
  }

  let result;
  try {
    result = await connect(args.target, {
      stdio: args.stdio,
      stdioArgs: args.stdioArgs,
      bearer: args.bearer,
    });
  } catch (err) {
    process.stderr.write(
      `toolfence: failed to connect to "${terminalText(args.target)}": ${terminalText(String((err as Error).message))}\n`,
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
    let checkFailed = false;
    for (const check of CHECKS) {
      try {
        findings.push(...(await check.run(ctx)));
      } catch (err) {
        checkFailed = true;
        findings.push({
          checkId: check.id,
          severity: "info",
          title: `Check "${check.id}" errored`,
          detail: (err as Error).message,
        });
      }
    }

    if (args.baseline && !checkFailed) {
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
      process.stdout.write(`toolfence: report written to ${terminalText(args.out)}\n`);
    } else {
      process.stdout.write(rendered + "\n");
    }

    const worst = worstSeverity(report) ??
      (report.counts.info > 0 ? "info" : null);
    if (checkFailed) return 2;
    if (
      args.failOn !== "off" &&
      worst !== null &&
      SEVERITY_ORDER.indexOf(worst) <= SEVERITY_ORDER.indexOf(args.failOn)
    ) {
      return 1;
    }
    return 0;
  } finally {
    await result.close().catch(() => {});
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`toolfence: fatal: ${terminalText(String(err?.stack ?? err))}\n`);
    process.exit(2);
  });
