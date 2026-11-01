// The upload budget, the unix-socket upstream (cloud mode), and /healthz.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createGate } from '../gate/gate.mjs';

const tmpdir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'budget-'));
const listen = (srv) => new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok(srv.address().port)));
const lines = (f) => fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

function connectVia(gatePort, target) {
  return new Promise((ok, bad) => {
    const s = net.connect(gatePort, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    let buf = '';
    s.on('data', (d) => {
      buf += d;
      const end = buf.indexOf('\r\n\r\n');
      if (end >= 0) { s.removeAllListeners('data'); ok({ s, head: buf.slice(0, end), rest: buf.slice(end + 4) }); }
    });
    s.on('error', bad);
  });
}
const closed = (s, ms = 1500) => new Promise((ok) => { s.on('close', () => ok(true)); setTimeout(() => ok(false), ms); });

// A target that swallows whatever it is sent.
async function sink() {
  const srv = net.createServer((s) => { s.on('data', () => {}); s.on('error', () => {}); });
  return { srv, port: await listen(srv) };
}

test('upload budget: a tunnel is cut when its host is sent too much, and the cut is receipted', async () => {
  const t = await sink();
  const file = path.join(tmpdir(), 'egress.jsonl');
  const g = createGate({ rules: ['localhost'], allowPrivate: true, receiptsFile: file, ports: [t.port], uploadBudget: 1000 });
  const gp = await listen(g.server);

  const { s, head } = await connectVia(gp, `localhost:${t.port}`);
  assert.match(head, /^HTTP\/1\.1 200/);
  s.write(Buffer.alloc(600));
  await sleep(100);
  assert.equal(s.destroyed, false, 'under budget: still open');
  s.write(Buffer.alloc(600));
  assert.equal(await closed(s), true, 'over budget: cut');

  const rs = lines(file);
  const hit = rs.find((r) => r.kind === 'budget-exceeded');
  assert.ok(hit, 'a budget-exceeded receipt exists');
  assert.equal(hit.host, 'localhost');
  assert.equal(hit.budget_bytes, 1000);
  g.close(); t.srv.close();
});

test('upload budget: once spent, new connections to that host are refused until the window passes', async () => {
  const t = await sink();
  const file = path.join(tmpdir(), 'egress.jsonl');
  const g = createGate({ rules: ['localhost'], allowPrivate: true, receiptsFile: file, ports: [t.port], uploadBudget: 500, budgetWindowMs: 400 });
  const gp = await listen(g.server);

  const first = await connectVia(gp, `localhost:${t.port}`);
  first.s.write(Buffer.alloc(800));
  await closed(first.s);

  const second = await connectVia(gp, `localhost:${t.port}`);
  assert.match(second.head, /^HTTP\/1\.1 403/);
  assert.match(second.head, /X-Gate-Reason: upload-budget/);
  assert.equal(lines(file).filter((r) => r.reason === 'upload-budget').length, 1);

  await sleep(450); // the window rolls over
  const third = await connectVia(gp, `localhost:${t.port}`);
  assert.match(third.head, /^HTTP\/1\.1 200/);
  third.s.destroy();
  g.close(); t.srv.close();
});

test('upload budget: 0 means no limit, and downloads are never counted', async () => {
  const big = net.createServer((s) => { s.write(Buffer.alloc(200_000)); s.on('error', () => {}); s.on('data', () => {}); });
  const bp = await listen(big);
  const file = path.join(tmpdir(), 'egress.jsonl');
  const g = createGate({ rules: ['localhost'], allowPrivate: true, receiptsFile: file, ports: [bp], uploadBudget: 1000 });
  const gp = await listen(g.server);
  const { s, rest } = await connectVia(gp, `localhost:${bp}`);
  let got = rest.length; s.on('data', (d) => (got += d.length));
  try {
    for (let i = 0; i < 60 && got < 200_000; i++) await sleep(50); // wait for the download, up to 3 s
    assert.ok(got >= 200_000, `received ${got} bytes: a 200 KB download is under no upload budget`);
    assert.equal(s.destroyed, false);
  } finally { s.destroy(); g.close(); big.close(); }

  const t = await sink();
  const g2 = createGate({ rules: ['localhost'], allowPrivate: true, receiptsFile: path.join(tmpdir(), 'e.jsonl'), ports: [t.port], uploadBudget: 0 });
  const gp2 = await listen(g2.server);
  const { s: s2 } = await connectVia(gp2, `localhost:${t.port}`);
  try {
    s2.write(Buffer.alloc(500_000));
    await sleep(200);
    assert.equal(s2.destroyed, false, 'budget 0: unlimited');
  } finally { s2.destroy(); g2.close(); t.srv.close(); }
});

test('/healthz reports the live chain head and the budget', async () => {
  const file = path.join(tmpdir(), 'egress.jsonl');
  const g = createGate({ rules: ['a.example', 'b.example'], receiptsFile: file, uploadBudget: 100 * 1048576 });
  g.announce();
  const gp = await listen(g.server);
  const body = await new Promise((ok) => http.get({ host: '127.0.0.1', port: gp, path: '/healthz' }, (r) => { let b = ''; r.on('data', (d) => (b += d)); r.on('end', () => ok(b)); }));
  assert.match(body, /^ok rules=2 head=[0-9a-f]{64} budget_mb=100\n$/);
  assert.ok(body.includes(g.head()));
  g.close();
});

test('/healthz goes 503 when receipts cannot be written — a gate that refuses everything must not look healthy', async () => {
  const getHealth = (port) => new Promise((ok) => http.get({ host: '127.0.0.1', port, path: '/healthz' }, (r) => { let b = ''; r.on('data', (d) => (b += d)); r.on('end', () => ok({ code: r.statusCode, b })); }));

  const dir = tmpdir();
  const good = createGate({ rules: ['a.example'], receiptsFile: path.join(dir, 'egress.jsonl') });
  const gp = await listen(good.server);
  assert.equal((await getHealth(gp)).code, 200);
  good.close();

  const bad = createGate({ rules: ['a.example'], receiptsFile: path.join(dir, 'no-such-dir', 'egress.jsonl') });
  const bp = await listen(bad.server);
  const h = await getHealth(bp);
  assert.equal(h.code, 503);
  assert.match(h.b, /receipts-unwritable/);
  assert.equal(bad.announce(), false, 'announce reports the failure so main can say so out loud');
  bad.close();
});

// --- cloud mode: the upstream proxy is a unix socket --------------------------------

function fakeUpstream(sock, status = 200) {
  const seen = [];
  const srv = net.createServer((s) => {
    s.once('data', (d) => {
      seen.push(d.toString().split('\r\n')[0]);
      if (status !== 200) return s.end(`HTTP/1.1 ${status} No\r\nContent-Length: 0\r\n\r\n`);
      s.write('HTTP/1.1 200 OK\r\n\r\n');
      s.on('data', (x) => s.write(x)); // echo
    });
    s.on('error', () => {});
  });
  return new Promise((ok) => srv.listen(sock, () => ok({ srv, seen })));
}

test('unix-socket upstream: an allowed name tunnels through it, and the allowlist still decides first', async () => {
  const dir = tmpdir();
  const sock = path.join(dir, 'relay.sock');
  const up = await fakeUpstream(sock);
  const file = path.join(dir, 'egress.jsonl');
  const g = createGate({ rules: ['anything.example'], receiptsFile: file, upstream: `unix:${sock}` });
  const gp = await listen(g.server);

  const { s, head } = await connectVia(gp, 'anything.example:443');
  assert.match(head, /^HTTP\/1\.1 200/);
  const echo = await new Promise((ok) => { s.once('data', (d) => ok(String(d))); s.write('ping'); });
  assert.equal(echo, 'ping');
  s.destroy();

  const other = await connectVia(gp, 'other.example:443');
  assert.match(other.head, /X-Gate-Reason: not-on-allowlist/);
  await sleep(50);
  assert.deepEqual(up.seen, ['CONNECT anything.example:443 HTTP/1.1'], 'the upstream never saw the blocked host');
  g.close(); up.srv.close();
});

test('unix-socket upstream: a refusing upstream becomes a 502 and a receipt', async () => {
  const dir = tmpdir();
  const sock = path.join(dir, 'relay.sock');
  const up = await fakeUpstream(sock, 403);
  const file = path.join(dir, 'egress.jsonl');
  const g = createGate({ rules: ['anything.example'], receiptsFile: file, upstream: `unix:${sock}` });
  const gp = await listen(g.server);
  const { head } = await connectVia(gp, 'anything.example:443');
  assert.match(head, /^HTTP\/1\.1 502/);
  assert.equal(lines(file).at(-1).error, 'upstream-403');
  g.close(); up.srv.close();
});

test('a missing upstream socket fails closed (502), never falls back to a direct connection', async () => {
  const dir = tmpdir();
  const file = path.join(dir, 'egress.jsonl');
  const g = createGate({ rules: ['registry.npmjs.org'], receiptsFile: file, upstream: `unix:${path.join(dir, 'gone.sock')}` });
  const gp = await listen(g.server);
  const { head } = await connectVia(gp, 'registry.npmjs.org:443');
  assert.match(head, /^HTTP\/1\.1 502/);
  g.close();
});

test('a malformed upstream refuses to build the gate', () => {
  assert.throws(() => createGate({ rules: ['a.example'], receiptsFile: '/tmp/x.jsonl', upstream: 'not a url' }));
});
