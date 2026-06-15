# mcpguard

**Security scanner for MCP servers.** Point it at any [Model Context Protocol](https://modelcontextprotocol.io) server and get a severity-ranked report of the risks your agents inherit by connecting to it.

```bash
npx mcpguard https://your-server.example.com/mcp
```

```
  mcpguard — scan report
  target:  https://your-server.example.com/mcp
  server:  acme-tools v1.4.0 (http)
  tools:   22

  CRIT  Injection signature in tool definition  [fetch_doc]
        Tool "fetch_doc" contains language matching: instruction override.
        Tool descriptions are fed verbatim into the agent's context — this is
        a tool-poisoning vector.
  HIGH  No authentication required
  HIGH  Tool definition changed since baseline  [search]
  MED   Large tool catalog
  ...
  summary: 1 critical  2 high  1 medium  4 low  6 info
```

Exit code is non-zero when high/critical findings exist, so it drops straight into CI.

---

## Why

OAuth authenticated your agents. It didn't make them **safe**. The MCP spec settled authentication (OAuth 2.1 for HTTP transports) — but that's roughly 20% of the threat surface. The other 80% lives in what the tools *do* and what their definitions *say*:

- **Tool poisoning** — a malicious server ships a tool description that instructs the agent to read your secrets or ignore prior instructions. The agent reads it and complies.
- **Indirect prompt injection** — adversarial text smuggled into tool definitions or schemas.
- **Silent tool drift** — a server changes a tool definition after you trusted it.
- **Context-cost runaway** — a bloated tool catalog that's prepended to every agent turn.
- **Over-broad capability** — tools that touch the filesystem, execute code, or reach the network with no scoping.

`mcpguard` is the open-source scanner that surfaces these before you connect an agent to a server.

## Install

Run without installing:

```bash
npx mcpguard <url>
```

Or install globally:

```bash
npm install -g mcpguard
mcpguard <url>
```

## Usage

```bash
# Remote server (Streamable HTTP, falls back to SSE)
mcpguard https://example.com/mcp

# Authenticated server
mcpguard https://example.com/mcp --bearer "$TOKEN"

# Local stdio server (everything after --stdio is the command)
mcpguard --stdio npx -y @modelcontextprotocol/server-everything

# Machine-readable output for CI / dashboards
mcpguard https://example.com/mcp --json
mcpguard https://example.com/mcp --markdown -o report.md
```

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
| `2` | Scan could not run (connection / usage error) |

## What it checks (v0.1)

| Check | What it catches |
|-------|-----------------|
| **Authentication posture** | HTTP server that lists tools with no credentials |
| **Transport security** | Plaintext HTTP for non-local endpoints |
| **Prompt-injection signatures** | Adversarial instructions embedded in tool definitions |
| **Tool integrity / drift** | Tool definitions that changed since the last scan |
| **Context cost** | Tool catalogs large enough to inflate every agent turn |
| **Rate-limit posture** | No server-side ceiling on call volume |
| **Naming hygiene** | Duplicate or collision-prone generic tool names |
| **Sensitive capability** | Tools that reach the filesystem, execute code, or touch the network |

### Drift detection

The first scan of a target records a fingerprint of every tool definition under
`~/.mcpguard/baselines/`. Subsequent scans of the same target compare against it
and flag any tool whose definition changed, appeared, or disappeared — the core
signal for catching a server that turns malicious *after* you trusted it. Run it
in CI to fail the build on unexpected drift.

## Roadmap

v0.1 is the open-source scanner. It's the front end of a larger effort: a hosted
**security & governance gateway** that sits in front of your MCP servers and
enforces these properties at runtime — output sanitization, per-call scope
reduction, behavioral guardrails (rate/cost ceilings), capability-based
sub-agent delegation, and replayable audit. The scanner tells you what's wrong;
the gateway stops it in production.

## License

[Apache 2.0](./LICENSE).
