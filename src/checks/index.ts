// The mcpguard v0.1 check suite. Each check is pure over ScanContext and
// returns zero or more findings. Keep checks independent and side-effect free
// (baseline persistence is handled by the runner, not the checks).

import { createHash } from "node:crypto";
import { encode } from "gpt-tokenizer";
import type { Check, Finding, ScanContext, ToolInfo } from "../types.js";

function toolText(t: ToolInfo): string {
  return [t.name, t.description ?? "", JSON.stringify(t.inputSchema ?? {})].join(
    "\n",
  );
}

export function fingerprint(t: ToolInfo): string {
  return createHash("sha256").update(toolText(t)).digest("hex").slice(0, 16);
}

// ── 1. Auth posture ─────────────────────────────────────────────────────────
const authPosture: Check = {
  id: "auth-posture",
  title: "Authentication posture",
  run(ctx) {
    const f: Finding[] = [];
    const { connection: c } = ctx;
    if (c.transport === "stdio") {
      f.push({
        checkId: this.id,
        severity: "info",
        title: "Local stdio transport",
        detail:
          "Server runs as a local process; transport auth is not applicable. Trust derives from the binary you launch.",
      });
      return f;
    }
    // HTTP: we connected with no bearer and it still served us.
    if (!c.authProvided) {
      f.push({
        checkId: this.id,
        severity: "high",
        title: "No authentication required",
        detail:
          "The server accepted an MCP session and listed tools without any credentials. Anyone who can reach this URL can invoke its tools.",
        remediation:
          "Require OAuth 2.1 (per the 2025 MCP spec for HTTP transports) or at minimum a bearer token. Disable anonymous Dynamic Client Registration.",
      });
    }
    return f;
  },
};

// ── 2. Tool description integrity / drift ────────────────────────────────────
const toolIntegrity: Check = {
  id: "tool-integrity",
  title: "Tool description integrity",
  run(ctx) {
    const f: Finding[] = [];
    if (!ctx.baseline) {
      f.push({
        checkId: this.id,
        severity: "info",
        title: "Baseline established",
        detail:
          `Recorded fingerprints for ${ctx.tools.length} tool(s). Re-run to detect tool-definition drift.`,
      });
      return f;
    }
    const prev = ctx.baseline.toolFingerprints;
    const now = new Map(ctx.tools.map((t) => [t.name, fingerprint(t)]));

    for (const [name, hash] of now) {
      if (!(name in prev)) {
        f.push({
          checkId: this.id,
          severity: "medium",
          title: "New tool appeared since baseline",
          detail: `Tool "${name}" was not present in the recorded baseline.`,
          tool: name,
        });
      } else if (prev[name] !== hash) {
        f.push({
          checkId: this.id,
          severity: "high",
          title: "Tool definition changed since baseline",
          detail: `Tool "${name}" has a different fingerprint than the baseline (description or input schema changed). Silent tool redefinition is a poisoning vector.`,
          tool: name,
          remediation:
            "Re-review the tool definition. Pin trusted server versions and alert on drift in CI.",
        });
      }
    }
    for (const name of Object.keys(prev)) {
      if (!now.has(name)) {
        f.push({
          checkId: this.id,
          severity: "low",
          title: "Tool removed since baseline",
          detail: `Tool "${name}" from the baseline is no longer offered.`,
          tool: name,
        });
      }
    }
    return f;
  },
};

// ── 3. Prompt-injection signatures ───────────────────────────────────────────
// Injection detection targets adversarial *instructions* embedded in a tool
// definition — not the mere presence of sensitive capability nouns (those are
// handled by sensitive-scope). Keeping this to imperative/deceptive phrasing
// keeps precision high so the findings are trustworthy.
const INJECTION_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|preceding)\s+(instructions|prompts|messages)/i, label: "instruction override" },
  { re: /disregard\s+(all\s+)?(the\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules)/i, label: "instruction override" },
  { re: /(reveal|print|repeat|expose|output)\s+(your|the)\s+(system|developer)\s+prompt/i, label: "system-prompt extraction" },
  { re: /(read|load|cat|print|send|exfiltrate)\b[^.]{0,40}\b(\.env|environment\s+variables?|api[_\s-]?keys?|secrets?|credentials?)/i, label: "credential exfiltration instruction" },
  { re: /exfiltrat|leak\s+(the|all)|send\s+(the\s+)?(contents|data|file)\s+to\s+\S+@|email\s+\S+@/i, label: "exfiltration instruction" },
  { re: /<\s*(important|secret|system|hidden)\s*>|\[\[\s*system|<!--\s*inject/i, label: "hidden directive markup" },
  { re: /do\s+not\s+(tell|inform|mention|reveal|notify|show)\s+(this\s+to\s+)?(the\s+)?user/i, label: "user-concealment instruction" },
  { re: /before\s+(using|calling)\s+this\s+tool[,.]?\s+(you\s+must|first|always)\b/i, label: "coercive pre-instruction" },
];

const promptInjection: Check = {
  id: "prompt-injection",
  title: "Prompt-injection signatures in tool definitions",
  run(ctx) {
    const f: Finding[] = [];
    for (const t of ctx.tools) {
      const text = `${t.description ?? ""}\n${JSON.stringify(t.inputSchema ?? {})}`;
      const hits = INJECTION_PATTERNS.filter((p) => p.re.test(text)).map(
        (p) => p.label,
      );
      if (hits.length) {
        f.push({
          checkId: this.id,
          severity: "critical",
          title: "Injection signature in tool definition",
          detail: `Tool "${t.name}" contains language matching: ${[...new Set(hits)].join(", ")}. Tool descriptions are fed verbatim into the agent's context — this is a tool-poisoning vector.`,
          tool: t.name,
          remediation:
            "Do not connect agents to this server until reviewed. Tool descriptions should never instruct the agent to read secrets, override instructions, or hide actions from the user.",
        });
      }
    }
    return f;
  },
};

// ── 4. Context-window cost ───────────────────────────────────────────────────
const COST_WARN = 25_000;
const COST_HIGH = 50_000;

const contextCost: Check = {
  id: "context-cost",
  title: "Tool-catalog context cost",
  run(ctx) {
    const f: Finding[] = [];
    const catalog = JSON.stringify(
      ctx.tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    );
    let tokens: number;
    try {
      tokens = encode(catalog).length;
    } catch {
      // Fallback heuristic if tokenizer chokes on the payload.
      tokens = Math.ceil(catalog.length / 4);
    }
    const sev =
      tokens >= COST_HIGH ? "high" : tokens >= COST_WARN ? "medium" : "info";
    if (sev !== "info") {
      f.push({
        checkId: this.id,
        severity: sev,
        title: "Large tool catalog",
        detail: `The full tool catalog is ~${tokens.toLocaleString()} tokens across ${ctx.tools.length} tool(s). This is prepended to every agent turn, inflating cost and latency and degrading tool selection.`,
        remediation:
          "Trim or paginate tools, shorten descriptions, or gate tools behind capability scopes.",
      });
    } else {
      f.push({
        checkId: this.id,
        severity: "info",
        title: "Tool-catalog cost",
        detail: `~${tokens.toLocaleString()} tokens across ${ctx.tools.length} tool(s).`,
      });
    }
    return f;
  },
};

// ── 5. Rate-limit posture ────────────────────────────────────────────────────
const RATE_HEADERS = [
  "ratelimit",
  "ratelimit-limit",
  "x-ratelimit-limit",
  "retry-after",
  "x-rate-limit-limit",
];

const rateLimit: Check = {
  id: "rate-limit",
  title: "Rate-limit posture",
  run(ctx) {
    const f: Finding[] = [];
    if (ctx.connection.transport !== "http") return f;
    const h = ctx.connection.httpHeaders ?? {};
    const present = RATE_HEADERS.some((k) => k in h);
    if (!present) {
      f.push({
        checkId: this.id,
        severity: "low",
        title: "No rate-limit headers advertised",
        detail:
          "The endpoint exposed no standard rate-limit headers. An agent in a loop can hammer this server with no server-side ceiling, driving runaway cost.",
        remediation:
          "Advertise RateLimit headers (RFC 9239 draft) and enforce per-client quotas. Govern call volume at the gateway layer.",
      });
    }
    return f;
  },
};

// ── 6. Transport / TLS ───────────────────────────────────────────────────────
const transportTls: Check = {
  id: "transport-tls",
  title: "Transport security",
  run(ctx) {
    const f: Finding[] = [];
    const { connection: c } = ctx;
    if (c.transport !== "http" || !c.url) return f;
    if (c.url.protocol === "http:") {
      const local =
        c.url.hostname === "localhost" || c.url.hostname === "127.0.0.1";
      f.push({
        checkId: this.id,
        severity: local ? "low" : "critical",
        title: "Unencrypted transport",
        detail: local
          ? "Server is served over plaintext HTTP on localhost (acceptable for local dev, never for remote)."
          : "Server is served over plaintext HTTP. Tool calls, arguments, and responses — including any tokens — travel in cleartext.",
        remediation: "Serve the MCP endpoint over HTTPS only.",
      });
    }
    return f;
  },
};

// ── 7. Tool naming hygiene ───────────────────────────────────────────────────
const GENERIC_NAMES = new Set([
  "search", "query", "run", "exec", "execute", "get", "list", "read", "write",
  "call", "do", "action", "tool", "fetch",
]);

const namingHygiene: Check = {
  id: "naming-hygiene",
  title: "Tool naming hygiene",
  run(ctx) {
    const f: Finding[] = [];
    const seen = new Map<string, number>();
    for (const t of ctx.tools) {
      const key = t.name.toLowerCase();
      seen.set(key, (seen.get(key) ?? 0) + 1);
    }
    for (const [name, n] of seen) {
      if (n > 1) {
        f.push({
          checkId: this.id,
          severity: "medium",
          title: "Duplicate tool name",
          detail: `Tool name "${name}" is defined ${n} times. Name collisions let one tool shadow another — a hijacking vector.`,
          tool: name,
        });
      }
    }
    for (const t of ctx.tools) {
      if (GENERIC_NAMES.has(t.name.toLowerCase())) {
        f.push({
          checkId: this.id,
          severity: "low",
          title: "Collision-prone generic tool name",
          detail: `Tool "${t.name}" uses a generic name that is likely to collide when this server is combined with others in one agent.`,
          tool: t.name,
          remediation: "Namespace tool names (e.g. \"gmail_search\").",
        });
      }
    }
    return f;
  },
};

// ── 8. Sensitive scope detection ─────────────────────────────────────────────
// Matched against tool NAME + DESCRIPTION only (human-authored text), never the
// serialized JSON schema — schema keywords like "type"/"properties" produce
// noise. Patterns favor capability-revealing verbs/nouns over generic words.
const SENSITIVE: { re: RegExp; cap: string }[] = [
  { re: /\b(read|write|delete|list)?\s*(file|files|filesystem|directory|directories|folder)\b|\b(read_file|write_file|fs_)\w*/i, cap: "filesystem access" },
  { re: /\b(exec|execute|shell|bash|run\s+code|run_code|subprocess|terminal|spawn)\b|\bcommand\b/i, cap: "code/command execution" },
  { re: /\b(secret|secrets|credential|credentials|api[_\s-]?key|password|vault|environment\s+variable|\.env)\b/i, cap: "secret/credential access" },
  { re: /\b(http\s+request|fetch\s+a?\s*url|webhook|web\s+search|scrape|crawl|browse\s+the\s+web|download\s+from|upload\s+to)\b/i, cap: "outbound network" },
  { re: /\b(delete|drop\s+table|truncate|destroy|wipe|erase)\b/i, cap: "destructive operation" },
];

const sensitiveScope: Check = {
  id: "sensitive-scope",
  title: "Sensitive capability detection",
  run(ctx) {
    const f: Finding[] = [];
    for (const t of ctx.tools) {
      const text = `${t.name}\n${t.description ?? ""}`;
      const caps = [
        ...new Set(SENSITIVE.filter((s) => s.re.test(text)).map((s) => s.cap)),
      ];
      if (caps.length) {
        const dangerous = caps.some(
          (c) =>
            c === "code/command execution" ||
            c === "destructive operation" ||
            c === "secret/credential access",
        );
        f.push({
          checkId: this.id,
          severity: dangerous ? "medium" : "info",
          title: "Tool exposes sensitive capability",
          detail: `Tool "${t.name}" appears to provide: ${caps.join(", ")}. Confirm the agent is meant to have this reach, and that calls are scoped and audited.`,
          tool: t.name,
        });
      }
    }
    return f;
  },
};

export const CHECKS: Check[] = [
  authPosture,
  transportTls,
  promptInjection,
  toolIntegrity,
  contextCost,
  rateLimit,
  namingHygiene,
  sensitiveScope,
];
