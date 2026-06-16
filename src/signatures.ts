// Curated signatures of known-bad patterns seen in compromised or malicious
// MCP servers. This is a seed set — the value compounds as the community
// contributes real-world signatures. Matching is intentionally conservative:
// each signature targets a specific documented abuse pattern, not a vibe.

import type { Severity } from "./types.js";

export interface Signature {
  id: string;
  // Human-readable description of the known-bad pattern.
  label: string;
  severity: Severity;
  // Matched against a tool's combined name + description text.
  re: RegExp;
  reference?: string;
}

export const SIGNATURES: Signature[] = [
  {
    id: "sig-tool-poison-readfile-secrets",
    label:
      "Tool description instructs the agent to read local secret/config files (classic tool-poisoning payload)",
    severity: "critical",
    re: /\b(read|open|cat|load|fetch|access|exfiltrat)\w*\b.{0,60}?(\.ssh|id_rsa|\.aws\/credentials|\.env\b|cursor\.json|mcp\.json|claude_desktop_config)/i,
    reference: "Invariant Labs tool-poisoning disclosure, 2025",
  },
  {
    id: "sig-rug-pull-conditional",
    label:
      "Tool description contains conditional/time-gated behavior change ('after N uses', 'on the Nth call') — rug-pull pattern",
    severity: "high",
    re: /\b(after|once|on)\s+(the\s+)?\d+\s*(uses?|calls?|invocations?|times?|days?)\b/i,
    reference: "MCP rug-pull / delayed-activation pattern",
  },
  {
    id: "sig-cross-tool-shadow",
    label:
      "Tool description references or overrides another named tool ('instead of', 'override the X tool') — cross-tool shadowing",
    severity: "high",
    re: /\b(instead\s+of|override|replace|shadow|intercept)\s+(the\s+)?\w+\s+tool\b/i,
    reference: "MCP cross-server tool shadowing",
  },
  {
    id: "sig-data-to-external",
    label:
      "Tool description instructs sending data to a hardcoded external address/URL",
    severity: "critical",
    re: /\b(send|post|forward|upload|report|transmit)\b.{0,50}?(to\s+)?(https?:\/\/|[\w.-]+@[\w.-]+\.\w+)/i,
    reference: "MCP exfiltration-on-call pattern",
  },
  {
    id: "sig-base64-blob-instruction",
    label:
      "Tool description embeds a long base64/hex blob — obfuscated instruction smuggling",
    severity: "high",
    re: /[A-Za-z0-9+/]{120,}={0,2}/,
    reference: "Obfuscated-payload smuggling in tool metadata",
  },
];

export interface SignatureHit {
  signature: Signature;
}

export function matchSignatures(text: string): Signature[] {
  return SIGNATURES.filter((s) => s.re.test(text));
}
