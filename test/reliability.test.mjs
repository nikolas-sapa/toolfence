import test from 'node:test';
import assert from 'node:assert/strict';
import { encode } from 'gpt-tokenizer';
import { CHECKS, fingerprint } from '../dist/checks/index.js';
import { buildReport, renderTerminal, renderMarkdown, renderJsonSafe } from '../dist/report.js';
const context = tools => ({ connection: { transport: 'stdio', target: 'fixture', authProvided: false }, tools });
const check = id => CHECKS.find(c => c.id === id);
test('literal special-token markers cannot bypass high catalog-cost findings', async () => {
  const text = Array.from({ length: 60000 }, (_, i) => String.fromCharCode(0x4e00 + i % 2000)).join('') + '<|endoftext|>';
  const tools = [{ name: 'fixture', description: text }];
  const expected = encode(JSON.stringify(tools), { disallowedSpecial: new Set() }).length;
  assert.ok(expected > 50000);
  const findings = await check('context-cost').run(context(tools));
  assert.equal(findings[0].severity, 'high');
  assert.ok(findings[0].detail.includes(expected.toLocaleString()));
});
test('safety annotation changes alter tool fingerprint', async () => {
  const before = { name: 'fixture', annotations: { readOnlyHint: true } };
  const after = { name: 'fixture', annotations: { readOnlyHint: false, destructiveHint: true } };
  assert.notEqual(fingerprint(before), fingerprint(after));
  const findings = await check('tool-integrity').run({ ...context([after]), baseline: { target: 'fixture', createdAt: 'fixture', toolFingerprints: { fixture: fingerprint(before) } } });
  assert.ok(findings.some(f => f.severity === 'high'));
});
test('inherited baseline properties are treated as newly observed tools', async () => {
  const findings = await check('tool-integrity').run({ ...context([{ name: 'toString' }]), baseline: { target: 'fixture', createdAt: 'fixture', toolFingerprints: {} } });
  assert.ok(findings.some(f => /new tool/i.test(f.title)));
  assert.ok(!findings.some(f => /changed/i.test(f.title)));
});
test('sealed empty object schema does not claim arbitrary input acceptance', async () => {
  const findings = await check('schema-strength').run(context([{ name: 'ping', inputSchema: { type: 'object', properties: {}, additionalProperties: false } }]));
  assert.ok(!findings.some(f => /any input shape/i.test(f.detail)));
});
test('report rendering escapes remote terminal controls and Markdown markup', () => {
  const hostile = '\x1b[2J\u2060<img src=x>\n| forged | row |`';
  const report = buildReport(hostile, 'stdio', 1, [{ checkId: hostile, severity: 'high', title: hostile, tool: hostile, detail: hostile, remediation: hostile }], hostile, hostile);
  for (const color of [true, false]) {
    const rendered = renderTerminal(report, color);
    assert.ok(!rendered.includes('\x1b[2J'));
    assert.ok(!rendered.includes('\u2060'));
    assert.ok(!rendered.includes('\n| forged'));
  }
  const markdown = renderMarkdown(report);
  assert.ok(!markdown.includes('<img'));
  assert.ok(!markdown.includes('\n| forged'));
  assert.ok(!markdown.includes('\x1b'));
  assert.deepEqual(JSON.parse(renderJsonSafe(report)), report);
});
