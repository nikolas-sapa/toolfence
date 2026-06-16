// Core types for toolfence.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

// Behavioral hints a server may attach to a tool (MCP `annotations`).
export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

// A single MCP tool as reported by the server.
export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: ToolAnnotations;
}

// Transport/connection facts gathered while connecting, shared with checks.
export interface ConnectionContext {
  // "http" for Streamable HTTP / SSE endpoints, "stdio" for local processes.
  transport: "http" | "stdio";
  // Original target string (URL or command) the user passed.
  target: string;
  // Parsed URL when transport === "http".
  url?: URL;
  // Whether the connection was made without supplying any credentials.
  authProvided: boolean;
  // Raw response headers from the initial HTTP handshake, lowercased keys.
  httpHeaders?: Record<string, string>;
  // Server-advertised name/version from the MCP initialize result.
  serverName?: string;
  serverVersion?: string;
}

// What every check receives.
export interface ScanContext {
  connection: ConnectionContext;
  tools: ToolInfo[];
  // Persisted baseline from a previous run (for drift detection), if any.
  baseline?: Baseline;
}

export interface Finding {
  checkId: string;
  severity: Severity;
  title: string;
  detail: string;
  // Optional tool this finding is attributed to.
  tool?: string;
  // Optional remediation hint.
  remediation?: string;
}

export interface Check {
  id: string;
  title: string;
  run(ctx: ScanContext): Finding[] | Promise<Finding[]>;
}

// Persisted between runs for drift detection.
export interface Baseline {
  createdAt: string;
  target: string;
  // tool name -> fingerprint hash
  toolFingerprints: Record<string, string>;
}

export interface ScanReport {
  target: string;
  transport: string;
  serverName?: string;
  serverVersion?: string;
  toolCount: number;
  scannedAt: string;
  findings: Finding[];
  counts: Record<Severity, number>;
}
