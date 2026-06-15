// Baseline persistence for drift detection. Stored per-target under
// ~/.mcpguard/baselines/<hash>.json so re-running the same target compares
// against the last seen tool fingerprints.

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Baseline, ToolInfo } from "./types.js";
import { fingerprint } from "./checks/index.js";

function baselineDir(): string {
  return join(homedir(), ".mcpguard", "baselines");
}

function baselinePath(target: string): string {
  const h = createHash("sha256").update(target).digest("hex").slice(0, 24);
  return join(baselineDir(), `${h}.json`);
}

export async function loadBaseline(
  target: string,
): Promise<Baseline | undefined> {
  try {
    const raw = await readFile(baselinePath(target), "utf8");
    return JSON.parse(raw) as Baseline;
  } catch {
    return undefined;
  }
}

export async function saveBaseline(
  target: string,
  tools: ToolInfo[],
): Promise<void> {
  const baseline: Baseline = {
    createdAt: new Date().toISOString(),
    target,
    toolFingerprints: Object.fromEntries(
      tools.map((t) => [t.name, fingerprint(t)]),
    ),
  };
  await mkdir(baselineDir(), { recursive: true });
  await writeFile(baselinePath(target), JSON.stringify(baseline, null, 2));
}
