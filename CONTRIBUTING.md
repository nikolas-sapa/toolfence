# Contributing to mcpguard

The most valuable contribution is a **new known-bad signature**: a pattern seen
in a real malicious or compromised MCP server. The signature set is what makes
the scanner sharper than a generic linter, and it compounds with every report.

## Adding a signature

Signatures live in [`src/signatures.ts`](./src/signatures.ts). Each is one entry:

```ts
{
  id: "sig-short-stable-id",
  label: "One sentence describing the documented abuse pattern.",
  severity: "critical" | "high" | "medium" | "low",
  re: /a tight regex matched against tool name + description/i,
  reference: "Where this was observed / disclosed.",
}
```

### Rules for a good signature

1. **Target a documented pattern, not a vibe.** Every signature should map to a
   real abuse technique (tool poisoning, rug-pull, shadowing, exfiltration,
   payload smuggling). Put the source in `reference`.
2. **Favor precision over recall.** A signature that fires on benign tools is
   worse than no signature — it erodes trust in every report. When in doubt,
   tighten the regex and lower the severity.
3. **Mind word boundaries and punctuation.** File paths contain dots; verbs get
   inflected ("read" → "reads"). Don't let `\b...\b` or `[^.]` silently fail to
   match (`.{0,N}?` for gaps, `\w*` for verb suffixes).
4. **Add a test.** Every signature needs a positive case (fires on the attack)
   **and** a negative case (silent on a benign tool) in
   [`test/checks.test.mjs`](./test/checks.test.mjs).

## Dev loop

```bash
npm install
npm test          # builds, then runs the full suite
npm run build && node dist/index.js --stdio npx -y @modelcontextprotocol/server-everything
```

A PR is mergeable when `npm test` is green and the new signature has both test
cases. CI runs the same on every push.

## Reporting a malicious server

Found a server abusing the protocol in the wild? Open an issue with the server
identity, the offending tool definition, and the abuse it enables. Confirmed
cases become signatures that protect everyone downstream.
