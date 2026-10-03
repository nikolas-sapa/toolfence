// Baselines record the latest completed scan, not an immutable trust decision.
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, open, rename, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Baseline, ToolInfo } from "./types.js";
import { fingerprint } from "./checks/index.js";

function baselineDir(): string {
  return join(homedir(), ".toolfence", "baselines");
}

function baselinePath(target: string, directory: string): string {
  const h = createHash("sha256").update(target).digest("hex").slice(0, 24);
  return join(directory, `${h}.json`);
}

export async function loadBaseline(
  target: string,
  directory = baselineDir(),
): Promise<Baseline | undefined> {
  let raw: string;
  try {
    raw = await readFile(baselinePath(target, directory), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Invalid drift baseline JSON; repair it before scanning.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid drift baseline structure.");
  }
  const b = parsed as Partial<Baseline>;
  if (typeof b.target !== "string" || typeof b.createdAt !== "string" ||
      !b.toolFingerprints || typeof b.toolFingerprints !== "object" ||
      Array.isArray(b.toolFingerprints) ||
      !Object.values(b.toolFingerprints).every(hash => typeof hash === "string")) {
    throw new Error("Invalid drift baseline structure.");
  }
  return b as Baseline;
}

export async function saveBaseline(
  target: string,
  tools: ToolInfo[],
  directory = baselineDir(),
): Promise<void> {
  const baseline: Baseline = {
    createdAt: new Date().toISOString(),
    target,
    toolFingerprints: Object.fromEntries(tools.map(t => [t.name, fingerprint(t)])),
  };
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const file = baselinePath(target, directory);
  const tmp = `${file}.${randomUUID()}.tmp`;
  const handle = await open(tmp, "wx", 0o600);
  try {
    try {
      await handle.writeFile(JSON.stringify(baseline, null, 2));
    } finally {
      await handle.close();
    }
    await rename(tmp, file);
  } finally {
    await rm(tmp, { force: true });
  }
}
