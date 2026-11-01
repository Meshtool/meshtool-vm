// Receipts are a hash chain: tampering with the middle of the file is detectable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { createGate, verifyChain, sha256Hex } from '../gate/gate.mjs';

const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'chain-'));
const listen = (srv) => new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok(srv.address().port)));
const VERIFY = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'scripts', 'verify-receipts.mjs');

function refused(gatePort, target) {
  return new Promise((ok) => {
    const s = net.connect(gatePort, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\n\r\n`));
    s.once('data', () => { s.destroy(); ok(); });
  });
}

// A real gate writes a real file: some policy, some denials, a start line.
async function realReceipts(dir, n = 4) {
  const file = path.join(dir, 'egress.jsonl');
  const g = createGate({ rules: ['only.example'], receiptsFile: file });
  g.announce();
  const p = await listen(g.server);
  for (let i = 0; i < n; i++) await refused(p, `denied${i}.example:443`);
  g.close();
  return { file, text: fs.readFileSync(file, 'utf8'), head: g.head() };
}

test('a file written by the gate verifies, and its head is the gate\'s live head', async () => {
  const { text, head } = await realReceipts(tmpdir());
  const r = verifyChain(text);
  assert.equal(r.ok, true);
  assert.equal(r.count, 5);
  assert.equal(r.head, head);
});

test('editing a middle line is caught at the next line', async () => {
  const { text } = await realReceipts(tmpdir());
  const lines = text.trimEnd().split('\n');
  lines[2] = lines[2].replace('denied1.example', 'registry.npmjs.org');
  const r = verifyChain(lines.join('\n') + '\n');
  assert.equal(r.ok, false);
  assert.equal(r.line, 4);
});

test('deleting a middle line is caught', async () => {
  const { text } = await realReceipts(tmpdir());
  const lines = text.trimEnd().split('\n');
  lines.splice(2, 1);
  const r = verifyChain(lines.join('\n') + '\n');
  assert.equal(r.ok, false);
  assert.equal(r.line, 3);
});

test('reordering lines is caught', async () => {
  const { text } = await realReceipts(tmpdir());
  const lines = text.trimEnd().split('\n');
  [lines[1], lines[2]] = [lines[2], lines[1]];
  assert.equal(verifyChain(lines.join('\n') + '\n').ok, false);
});

test('a forged line appended without the right prev is caught', async () => {
  const { text } = await realReceipts(tmpdir());
  const forged = JSON.stringify({ ts: new Date().toISOString(), kind: 'egress', decision: 'allow', host: 'x.example' });
  assert.equal(verifyChain(text + forged + '\n').ok, false);
  const wrong = JSON.stringify({ ts: new Date().toISOString(), kind: 'egress', decision: 'allow', prev: 'f'.repeat(64) });
  assert.equal(verifyChain(text + wrong + '\n').ok, false);
});

test('a first line that does not start the chain is caught', async () => {
  const { text } = await realReceipts(tmpdir());
  const rest = text.split('\n').slice(1).join('\n');
  assert.equal(verifyChain(rest).ok, false);
});

test('garbage and blank lines are caught', async () => {
  const { text } = await realReceipts(tmpdir());
  assert.equal(verifyChain(text + 'not json\n').ok, false);
  assert.equal(verifyChain(text + '\n\n').ok, false);
});

test('the chain alone cannot see a cut tail — the live head can', async () => {
  const { text, head } = await realReceipts(tmpdir());
  const cut = text.trimEnd().split('\n').slice(0, 3).join('\n') + '\n';
  const r = verifyChain(cut);
  assert.equal(r.ok, true, 'a prefix of a valid chain is a valid chain');
  assert.equal(r.hashes.includes(head), false, 'but it no longer contains the gate\'s live head');
  // and editing the LAST line is invisible to the chain, but changes its hash:
  const lines = text.trimEnd().split('\n');
  lines[lines.length - 1] = lines[lines.length - 1].replace('denied3', 'denied9');
  const e = verifyChain(lines.join('\n') + '\n');
  assert.equal(e.ok, true);
  assert.equal(e.hashes.includes(head), false);
});

test('an empty file is a valid empty chain', () => {
  assert.deepEqual(verifyChain(''), { ok: true, count: 0, head: 'genesis', hashes: [] });
});

test('a restart picks the chain up where it left off', async () => {
  const dir = tmpdir();
  const file = path.join(dir, 'egress.jsonl');
  const a = createGate({ rules: ['only.example'], receiptsFile: file });
  a.announce();
  const pa = await listen(a.server); await refused(pa, 'one.example:443'); a.close();

  const b = createGate({ rules: ['only.example'], receiptsFile: file }); // new process, same file
  assert.equal(b.head(), a.head());
  b.announce();
  const pb = await listen(b.server); await refused(pb, 'two.example:443'); b.close();

  const r = verifyChain(fs.readFileSync(file, 'utf8'));
  assert.equal(r.ok, true);
  assert.equal(r.count, 4);
});

test('a receipt that fails to write does not advance the chain', () => {
  const dir = tmpdir();
  const file = path.join(dir, 'sub', 'egress.jsonl');
  fs.mkdirSync(path.dirname(file));
  const g = createGate({ rules: ['only.example'], receiptsFile: file });
  assert.equal(g.announce(), true);
  const before = g.head();
  fs.rmSync(path.dirname(file), { recursive: true });
  assert.equal(g.announce(), false);
  assert.equal(g.head(), before);
});

test('the policy that was in force is receipted by hash, at start and on reload', () => {
  const dir = tmpdir();
  const policy = path.join(dir, 'allow.txt');
  const file = path.join(dir, 'egress.jsonl');
  fs.writeFileSync(policy, 'one.example\n');
  const g = createGate({ policyFile: policy, receiptsFile: file });
  g.announce();
  fs.writeFileSync(policy, 'one.example\ntwo.example\n');
  g.reload();
  const rs = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(rs[0].kind, 'gate-start');
  assert.equal(rs[0].policy_sha256, sha256Hex('one.example\n'));
  assert.equal(rs[1].kind, 'policy-reload');
  assert.equal(rs[1].policy_sha256, sha256Hex('one.example\ntwo.example\n'));
});

// --- the command-line verifier -----------------------------------------------------

const run = (...args) => {
  try { return { code: 0, out: execFileSync('node', [VERIFY, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) }; }
  catch (e) { return { code: e.status, out: String(e.stdout) + String(e.stderr) }; }
};

test('verify-receipts: exit 0 on a good file, 1 when tampered, 2 on usage errors', async () => {
  const { file, text, head } = await realReceipts(tmpdir());
  const ok = run(file);
  assert.equal(ok.code, 0);
  assert.match(ok.out, /5 receipts, chain intact/);

  assert.equal(run(file, '--head', head).code, 0);
  assert.match(run(file, '--head', head).out, /matches the live gate/);
  assert.equal(run(file, '--head', 'a'.repeat(64)).code, 1, 'a head that is not in the file means the tail was cut');

  const lines = text.trimEnd().split('\n');
  lines[1] = lines[1].replace('denied0', 'tampered');
  fs.writeFileSync(file, lines.join('\n') + '\n');
  const bad = run(file);
  assert.equal(bad.code, 1);
  assert.match(bad.out, /BROKEN at line 3/);

  assert.equal(run('/nonexistent/file.jsonl').code, 2);
  assert.equal(run().code, 2);
});
