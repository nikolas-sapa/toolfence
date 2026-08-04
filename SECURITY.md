# Security Policy

toolfence scans MCP servers for security issues. A vulnerability in toolfence
itself — a flaw that causes it to miss a real threat, mis-parse a malicious
tool definition, or expose the scanning host to risk — deserves the same
seriousness as the issues it's built to catch.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **niksapa150@gmail.com** with:

- A description of the vulnerability and its impact
- Steps to reproduce (a minimal MCP server or tool definition that triggers it)
- The toolfence version and Node.js version used

You should get an acknowledgment within 5 business days. We'll work with you
on a fix and a disclosure timeline before any public write-up — please give
us a reasonable window to ship a patched release before disclosing publicly.
Credit is given in the release notes unless you ask to stay anonymous.

## Scope

In scope:

- Bypasses that let a malicious tool definition evade detection (false negative)
- Crashes, RCE, or resource exhaustion triggered by a hostile MCP server response
- Baseline/drift storage tampering (`~/.toolfence/baselines/`)

Out of scope:

- False positives (benign tools flagged) — file these as a normal issue
- Vulnerabilities in the MCP servers toolfence scans, not in toolfence itself

## Supported versions

Only the latest published release on npm is supported. toolfence is pre-1.0;
there are no maintained release branches. Upgrade before reporting if you're
not on the latest version.
