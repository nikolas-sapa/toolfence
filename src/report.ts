// Report assembly + rendering (terminal, Markdown, JSON).

import type {
  Finding,
  ScanReport,
  Severity,
} from "./types.js";
import { SEVERITY_ORDER } from "./types.js";

const COLOR: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[97m", // white on red bg
  high: "\x1b[31m", // red
  medium: "\x1b[33m", // yellow
  low: "\x1b[36m", // cyan
  info: "\x1b[90m", // gray
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";

const LABEL: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED ",
  low: "LOW ",
  info: "INFO",
};

export function buildReport(
  target: string,
  transport: string,
  toolCount: number,
  findings: Finding[],
  serverName?: string,
  serverVersion?: string,
): ScanReport {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) counts[f.severity]++;
  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  return {
    target,
    transport,
    serverName,
    serverVersion,
    toolCount,
    scannedAt: new Date().toISOString(),
    findings: sorted,
    counts,
  };
}

// Worst severity present, for exit codes / headline.
export function worstSeverity(r: ScanReport): Severity | null {
  for (const s of SEVERITY_ORDER) {
    if (r.counts[s] > 0 && s !== "info") return s;
  }
  return null;
}

export function renderTerminal(r: ScanReport, color: boolean): string {
  const c = (s: Severity, text: string) =>
    color ? `${COLOR[s]}${text}${RESET}` : text;
  const b = (text: string) => (color ? `${BOLD}${text}${RESET}` : text);

  const lines: string[] = [];
  lines.push("");
  lines.push(b(`  mcpguard — scan report`));
  lines.push(`  target:  ${r.target}`);
  lines.push(
    `  server:  ${r.serverName ?? "unknown"}${r.serverVersion ? ` v${r.serverVersion}` : ""} (${r.transport})`,
  );
  lines.push(`  tools:   ${r.toolCount}`);
  lines.push("");

  if (r.findings.length === 0) {
    lines.push(c("info", "  No findings."));
    lines.push("");
    return lines.join("\n");
  }

  for (const f of r.findings) {
    lines.push(
      `  ${c(f.severity, LABEL[f.severity])}  ${b(f.title)}${f.tool ? `  ${c("info", `[${f.tool}]`)}` : ""}`,
    );
    lines.push(`        ${f.detail}`);
    if (f.remediation) lines.push(`        ${c("info", "→ " + f.remediation)}`);
    lines.push("");
  }

  const summary = SEVERITY_ORDER.filter((s) => r.counts[s] > 0)
    .map((s) => c(s, `${r.counts[s]} ${s}`))
    .join("  ");
  lines.push(`  ${b("summary:")} ${summary || "clean"}`);
  lines.push("");
  return lines.join("\n");
}

export function renderJsonSafe(r: ScanReport): string {
  return JSON.stringify(r, null, 2);
}

export function renderMarkdown(r: ScanReport): string {
  const lines: string[] = [];
  lines.push(`# mcpguard scan report`);
  lines.push("");
  lines.push(`- **Target:** \`${r.target}\``);
  lines.push(
    `- **Server:** ${r.serverName ?? "unknown"}${r.serverVersion ? ` v${r.serverVersion}` : ""}`,
  );
  lines.push(`- **Transport:** ${r.transport}`);
  lines.push(`- **Tools:** ${r.toolCount}`);
  lines.push(`- **Scanned:** ${r.scannedAt}`);
  lines.push("");
  const summary = SEVERITY_ORDER.filter((s) => r.counts[s] > 0)
    .map((s) => `${r.counts[s]} ${s}`)
    .join(", ");
  lines.push(`**Summary:** ${summary || "no findings"}`);
  lines.push("");
  if (r.findings.length) {
    lines.push(`| Severity | Check | Tool | Finding |`);
    lines.push(`|---|---|---|---|`);
    for (const f of r.findings) {
      const detail = f.detail.replace(/\|/g, "\\|");
      lines.push(
        `| ${f.severity.toUpperCase()} | ${f.checkId} | ${f.tool ?? "—"} | ${detail} |`,
      );
    }
    lines.push("");
  }
  return lines.join("\n");
}
