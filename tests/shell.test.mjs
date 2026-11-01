// The shell log: a second hash chain with several short-lived writers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { appendChained, verifyChain } from '../gate/gate.mjs';

const root = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
const tmpfile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'shell-')), 'shell.jsonl');
const rows = (f) => fs.readFileSync(f, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

test('appendChained: records form a valid chain from genesis, and the lock is released', () => {
  const f = tmpfile();
  appendChained(f, { kind: 'shell-start', who: 'a' });
  appendChained(f, { kind: 'shell-end', who: 'a' });
  appendChained(f, { kind: 'shell-start', who: 'b' });
  const r = verifyChain(fs.readFileSync(f, 'utf8'));
  assert.equal(r.ok, true);
  assert.equal(r.count, 3);
  assert.equal(rows(f)[0].prev, 'genesis');
  assert.equal(fs.existsSync(`${f}.lock`), false);
});

test('appendChained: ten processes appending at once never fork the chain', async () => {
  const f = tmpfile();
  const script = `import { appendChained } from ${JSON.stringify(path.join(root, 'gate/gate.mjs'))};
    for (let i = 0; i < 6; i++) appendChained(${JSON.stringify(f)}, { kind: 'x', n: i, pid: process.pid });`;
  await Promise.all(Array.from({ length: 10 }, () => new Promise((ok, bad) => {
    const c = spawn('node', ['--input-type=module', '-e', script], { stdio: 'inherit' });
    c.on('exit', (code) => (code === 0 ? ok() : bad(new Error(`writer exited ${code}`))));
  })));
  const r = verifyChain(fs.readFileSync(f, 'utf8'));
  assert.equal(r.ok, true, `chain broken at line ${r.line}: ${r.error}`);
  assert.equal(r.count, 60);
});

test('appendChained: a busy lock fails closed; a stale one (a crashed writer) is cleared', () => {
  const f = tmpfile();
  fs.mkdirSync(`${f}.lock`);
  assert.throws(() => appendChained(f, { kind: 'x' }, { lockWaitMs: 150 }), /receipt lock busy/);
  assert.equal(fs.existsSync(f), false, 'nothing was written without the lock');

  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(`${f}.lock`, old, old);
  appendChained(f, { kind: 'x' }, { lockWaitMs: 500 });
  assert.equal(verifyChain(fs.readFileSync(f, 'utf8')).ok, true);
});

test('appendChained: editing the shell log is caught like any other receipts file', () => {
  const f = tmpfile();
  for (const k of ['a', 'b', 'c', 'd']) appendChained(f, { kind: 'shell-start', who: k });
  const lines = fs.readFileSync(f, 'utf8').trimEnd().split('\n');
  lines[1] = lines[1].replace('"who":"b"', '"who":"root"');
  assert.equal(verifyChain(lines.join('\n') + '\n').ok, false);
});

test('shell-receipt CLI: numbers stay numbers, who/where are added, bad input exits 2', () => {
  const f = tmpfile();
  const run = (...a) => { try { execFileSync('node', [path.join(root, 'scripts/shell-receipt.mjs'), ...a], { stdio: 'pipe' }); return 0; } catch (e) { return e.status; } };
  assert.equal(run(f, 'shell-end', 'mode=command', 'exit_code=3', 'seconds=12', 'program=npm', 'cmd_sha256='), 0);
  const r = rows(f)[0];
  assert.equal(r.kind, 'shell-end');
  assert.equal(r.exit_code, 3);
  assert.equal(r.seconds, 12);
  assert.equal(r.program, 'npm');
  assert.equal(r.cmd_sha256, '');
  assert.equal(r.user, os.userInfo().username);
  assert.equal(r.host, os.hostname());
  assert.equal(run(f), 2);
  assert.equal(run(f, 'shell-start', 'novalue'), 2);
  assert.equal(run('/nonexistent-dir/shell.jsonl', 'shell-start'), 1, 'an unwritable log is a non-zero exit, which vm-shell.sh turns into "no shell"');
});
