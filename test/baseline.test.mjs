import test, { after } from 'node:test';
import os from 'node:os';
import { syncBuiltinESMExports } from 'node:module';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, unlink, symlink, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { loadBaseline, saveBaseline } from '../dist/baseline.js';
const originalHomedir = os.homedir;
const fixtureHome = await mkdtemp(join(tmpdir(), 'toolfence-home-'));
os.homedir = () => fixtureHome;
syncBuiltinESMExports();
after(async () => {
  os.homedir = originalHomedir;
  syncBuiltinESMExports();
  await rm(fixtureHome, { recursive: true, force: true });
});
const target = 'fixture:controlled';
const filename = createHash('sha256').update(target).digest('hex').slice(0, 24) + '.json';
test('baseline I/O uses explicit fixture directory, private atomic files, no symlink target writes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'toolfence-baseline-'));
  try {
    await saveBaseline(target, [{ name: 'safe' }], dir);
    assert.deepEqual(await readdir(dir), [filename]);
    const file = join(dir, filename);
    const original = await loadBaseline(target, dir);
    assert.equal(original.target, target);
    if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o777, 0o600);
    const marker = join(dir, 'marker');
    await writeFile(marker, 'keep original');
    await unlink(file);
    await symlink(marker, file);
    await saveBaseline(target, [{ name: 'new' }], dir);
    assert.equal(await readFile(marker, 'utf8'), 'keep original');
    assert.ok(Object.hasOwn((await loadBaseline(target, dir)).toolFingerprints, 'new'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('corrupt or wrong-shaped baselines fail closed, missing baseline remains absent', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'toolfence-baseline-'));
  try {
    assert.equal(await loadBaseline(target, dir), undefined);
    const file = join(dir, filename);
    for (const data of ['{ broken', 'null', '{"createdAt":"x","target":"fixture","toolFingerprints":[]}']) {
      await writeFile(file, data);
      await assert.rejects(loadBaseline(target, dir));
      assert.equal(await readFile(file, 'utf8'), data);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
