# toolfence

[![npm version](https://img.shields.io/npm/v/toolfence.svg?style=flat-square&color=0B0B0D&labelColor=0B0B0D)](https://www.npmjs.com/package/toolfence)
[![CI](https://github.com/nikolas-sapa/toolfence/actions/workflows/ci.yml/badge.svg)](https://github.com/nikolas-sapa/toolfence/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-0B0B0D?style=flat-square&labelColor=0B0B0D)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20.3-0B0B0D?style=flat-square&labelColor=0B0B0D)](./package.json)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-0B0B0D?style=flat-square&labelColor=0B0B0D)](./CONTRIBUTING.md)

**Security scanner for MCP servers.** Point it at any [Model Context Protocol](https://modelcontextprotocol.io) server and get a severity-ranked report of the risks your agents inherit by connecting to it.

```bash
npx toolfence https://your-server.example.com/mcp
```

```
  toolfence — scan report
  target:  https://your-server.example.com/mcp
  server:  acme-tools v1.4.0 (http)
  tools:   22

  CRIT  Injection signature in tool definition  [fetch_doc]
        Tool "fetch_doc" contains language matching: instruction override.
        Tool descriptions are fed verbatim into the agent's context — this is
        a tool-poisoning vector.
  HIGH  No credentials required for tool discovery
  HIGH  Tool definition changed since baseline  [search]
  MED   Large tool catalog
  ...
  summary: 1 critical  2 high  1 medium  4 low  6 info
```

Exit code is non-zero when high/critical findings exist, so it drops straight into CI.

---

## Why

Authentication alone does not establish tool safety. Tool definitions can expose additional risks:

- **Tool poisoning** — a malicious server ships a tool description that instructs the agent to read your secrets or ignore prior instructions. The agent reads it and complies.
- **Indirect prompt injection** — adversarial text smuggled into tool definitions or schemas.
- **Silent tool drift** — a server changes a tool definition after you trusted it.
- **Context-cost runaway** — a bloated tool catalog that's prepended to every agent turn.
- **Over-broad capability** — tools that touch the filesystem, execute code, or reach the network with no scoping.

`toolfence` is the open-source scanner that surfaces these before you connect an agent to a server.

## Install

Run without installing:

```bash
npx toolfence <url>
```

Or install globally:

```bash
npm install -g toolfence
toolfence <url>
```

## Usage

```bash
# Remote server (Streamable HTTP, falls back to SSE)
toolfence https://example.com/mcp

# Authenticated server
toolfence https://example.com/mcp --bearer "$TOKEN"

# Local stdio server (everything after --stdio is the command)
toolfence --stdio npx -y @modelcontextprotocol/server-everything
toolfence --json --no-baseline --stdio node server.js "argument with spaces"

# Machine-readable output for CI / dashboards
toolfence https://example.com/mcp --json
toolfence https://example.com/mcp --markdown -o report.md
```

Requires Node 20.3 or newer for [combined abort signals](https://nodejs.org/download/release/v20.20.1/docs/api/globals.html#static-method-abortsignalanysignals).
Place scanner options before `--stdio`. Every subsequent argument goes unchanged
to the child server, including `--help`. Connection, handshake and catalog paging
share a 30-second deadline; the initial HTTP header probe is capped at 5 seconds.
Stdio commands run with your user permissions; the scanner does not sandbox them.

### Options

| Flag | Description |
|------|-------------|
| `--bearer <token>` | Bearer token for authenticated servers |
| `--json` | Emit machine-readable JSON |
| `--markdown`, `--md` | Emit a Markdown report |
| `-o, --out <file>` | Write the report to a file |
| `--no-baseline` | Don't read/write the drift-detection baseline |
| `--no-color` | Disable ANSI colors |
| `-h, --help` | Show help |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No high/critical findings |
| `1` | At least one high or critical finding |
| `2` | Scan incomplete (connection, usage, baseline or check error) |

## What it checks (12)

| Check | What it catches |
|-------|-----------------|
| **Authentication posture** | HTTP server that lists tools with no credentials |
| **Transport security** | Plaintext HTTP for non-local endpoints |
| **Prompt-injection signatures** | Adversarial instructions embedded in tool definitions |
| **Known-bad signatures** | Documented MCP abuse patterns (secret-file reads, rug-pulls, cross-tool shadowing, exfiltration-to-external, obfuscated payloads) |
| **Tool integrity / drift** | Tool definitions that changed since the last scan |
| **Context cost** | Tool catalogs large enough to inflate every agent turn |
| **Rate-limit posture** | Missing rate-limit headers on the initial HTTP probe |
| **Naming hygiene** | Duplicate or collision-prone generic tool names |
| **Sensitive capability** | Tools that reach the filesystem, execute code, or touch the network |
| **Schema strength** | Missing, untyped, or unsealed input schemas |
| **Safety annotations** | Tools lacking `readOnlyHint` / `destructiveHint` so writes can't be gated |
| **Unicode hygiene** | Zero-width / bidi / homoglyph characters used to hide instructions or spoof trusted tools |

The [known-bad signature set](./src/signatures.ts) is community-extensible — see [CONTRIBUTING](./CONTRIBUTING.md).

Checks inspect server metadata and tool definitions; they do not invoke tools.
Anonymous catalog discovery does not prove anonymous tool execution. Missing
rate-limit headers do not prove absent enforcement. Findings are heuristics,
not a guarantee that a server is safe or unsafe.

### Drift detection

Each completed scan records tool fingerprints under `~/.toolfence/baselines/`.
The next scan compares names, descriptions, input schemas and safety annotations
against that latest observation. Changes, additions and removals produce findings.
Completed scans replace the baseline even when high/critical findings exist;
this is not an immutable record of approved tools. Incomplete discovery or failed
checks exit 2 without replacing it. Malformed or unreadable baselines fail the scan.

Writes use a private temporary file and atomic replacement. Reports and baselines
retain the target URL or command arguments: avoid embedding credentials in them.
`--bearer` avoids storing the token in the target, but command-line arguments may
still be visible to local process inspection. Use `--no-baseline` to skip caching.

Upgrading from earlier versions can flag one-time drift for annotated tools.
Stdio targets now use JSON-quoted argument tokens as their cache identity, so
their first scan establishes a new baseline. Annotation-free HTTP fingerprints
retain their previous format.

## Roadmap

v0.1 is the open-source scanner. It's the front end of a larger effort: a hosted
**security & governance gateway** that sits in front of your MCP servers and
enforces these properties at runtime — output sanitization, per-call scope
reduction, behavioral guardrails (rate/cost ceilings), capability-based
sub-agent delegation, and replayable audit. The scanner tells you what's wrong;
the gateway stops it in production.

## Contributing

The most valuable contribution is a new known-bad signature — a documented
MCP abuse pattern the scanner should catch. See [CONTRIBUTING.md](./CONTRIBUTING.md)
for the signature format, dev loop, and PR expectations.

## Security

Found a vulnerability in toolfence itself? Don't file a public issue — see
[SECURITY.md](./SECURITY.md) for how to report it.

## License

[Apache 2.0](./LICENSE).
