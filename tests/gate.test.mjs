// Run: npm test   (zero deps, no Docker needed)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parsePolicy, decide, isPrivateIP, createGate } from '../gate/gate.mjs';

const R = parsePolicy('# comment\nregistry.npmjs.org\n*.github.com  # trailing\n\n');

test('policy parses names and wildcards, ignores comments', () => {
  assert.deepEqual(R, ['registry.npmjs.org', '*.github.com']);
});

test('a bad policy line refuses to load (no silent half-policy)', () => {
  assert.throws(() => parsePolicy('good.com\nhttp://bad.com/path'), /bad policy line/);
});

test('exact and wildcard matches allow', () => {
  assert.equal(decide(R, 'registry.npmjs.org', 443).allow, true);
  assert.equal(decide(R, 'API.GitHub.com.', 443).allow, true);
});

test('lookalikes and apex-of-wildcard are blocked', () => {
  assert.equal(decide(R, 'evilgithub.com', 443).allow, false);
  assert.equal(decide(R, 'github.com', 443).allow, false);
  assert.equal(decide(R, 'registry.npmjs.org.evil.com', 443).allow, false);
});

test('IP literals, odd ports and junk hosts are blocked', () => {
  assert.equal(decide(R, '140.82.112.3', 443).reason, 'ip-literal');
  assert.equal(decide(R, '[::1]', 443).reason, 'bad-host');
  assert.equal(decide(R, 'registry.npmjs.org', 22).reason, 'port');
  assert.equal(decide(R, '', 443).reason, 'bad-host');
});

test('an empty policy blocks everything', () => {
  assert.equal(decide([], 'registry.npmjs.org', 443).reason, 'no-policy');
});

test('private, loopback, link-local and mapped addresses are recognised', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.18.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', '::', 'fc00::1', 'fd12::1', 'fe80::1', '::ffff:10.0.0.1', 'not-an-ip']) {
    assert.equal(isPrivateIP(ip), true, ip);
  }
  for (const ip of ['140.82.112.3', '104.16.0.1', '172.15.0.1', '172.32.0.1', '2606:4700::1', '::ffff:8.8.8.8']) {
    assert.equal(isPrivateIP(ip), false, ip);
  }
});

// --- the real server, in process ---------------------------------------------------

function tmp(name) {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gate-')), name);
}
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

// Tests tunnel to a server on 127.0.0.1, so they opt out of the private-address
// refusal; one test below proves the refusal is on by default.
// DNS is stubbed so these tests do not depend on the machine's resolver. (On a machine
// with IPv6 loopback, `localhost` resolves to ::1 first; the servers below listen on
// 127.0.0.1 only. That difference is exactly what once made CI hang while a laptop passed.)
const V4 = async () => [{ address: '127.0.0.1', family: 4 }];
const LOCAL = { rules: ['localhost'], allowPrivate: true, lookup: V4 };

test('allowed CONNECT tunnels and leaves allow + close receipts, with the resolved ip', async () => {
  const target = http.createServer((q, r) => r.end('hello from target'));
  const tPort = await listen(target);
  const receipts = tmp('egress.jsonl');
  const g = createGate({ ...LOCAL, receiptsFile: receipts, ports: [tPort] });
  const gPort = await listen(g.server);

  const { s, head } = await connectVia(gPort, `localhost:${tPort}`);
  assert.match(head, /^HTTP\/1\.1 200/);
  s.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  const body = await new Promise((ok) => { let b = ''; s.on('data', (d) => (b += d)); s.on('end', () => ok(b)); });
  assert.match(body, /hello from target/);
  await sleep(50);

  const rs = lines(receipts);
  assert.equal(rs[0].decision, 'allow');
  assert.equal(rs[0].host, 'localhost');
  assert.ok(isPrivateIP(rs[0].ip), 'receipt carries the resolved address');
  assert.equal(rs.at(-1).kind, 'egress-close');
  assert.ok(rs.at(-1).bytes_down > 0);
  g.close(); target.close();
});

test('blocked CONNECT gets 403 with a reason, and a deny receipt', async () => {
  const receipts = tmp('egress.jsonl');
  const g = createGate({ ...LOCAL, receiptsFile: receipts });
  const gPort = await listen(g.server);
  const { head } = await connectVia(gPort, 'example.com:443');
  assert.match(head, /^HTTP\/1\.1 403/);
  assert.match(head, /X-Gate-Reason: not-on-allowlist/);
  assert.deepEqual(
    (({ decision, host, reason }) => ({ decision, host, reason }))(lines(receipts)[0]),
    { decision: 'deny', host: 'example.com', reason: 'not-on-allowlist' },
  );
  g.close();
});

test('an allowed name that resolves to a private address is refused by default', async () => {
  const target = http.createServer((q, r) => r.end('should never be reached'));
  const tPort = await listen(target);
  let reached = false; target.on('connection', () => (reached = true));
  const receipts = tmp('egress.jsonl');
  const g = createGate({ rules: ['localhost'], receiptsFile: receipts, ports: [tPort], lookup: V4 });
  const gPort = await listen(g.server);
  const { head } = await connectVia(gPort, `localhost:${tPort}`);
  assert.match(head, /^HTTP\/1\.1 403/);
  assert.match(head, /X-Gate-Reason: private-ip/);
  assert.equal(reached, false);
  assert.equal(lines(receipts)[0].reason, 'private-ip');
  g.close(); target.close();
});

test('FAIL CLOSED: an unwritable receipts file blocks even an allowed host', async () => {
  const target = http.createServer((q, r) => r.end('should never be reached'));
  const tPort = await listen(target);
  let reached = false; target.on('connection', () => (reached = true));
  const g = createGate({ ...LOCAL, receiptsFile: '/nonexistent-dir/egress.jsonl', ports: [tPort] });
  const gPort = await listen(g.server);
  const { head } = await connectVia(gPort, `localhost:${tPort}`);
  assert.match(head, /^HTTP\/1\.1 403/);
  assert.match(head, /receipt-unwritable/);
  assert.equal(reached, false);
  g.close(); target.close();
});

test('FAIL CLOSED: a missing policy file blocks everything', async () => {
  const receipts = tmp('egress.jsonl');
  const g = createGate({ policyFile: '/nonexistent/allow.txt', receiptsFile: receipts });
  const gPort = await listen(g.server);
  const { head } = await connectVia(gPort, 'registry.npmjs.org:443');
  assert.match(head, /X-Gate-Reason: no-policy/);
  g.close();
});

test('FAIL CLOSED: a malformed policy at start refuses to start', () => {
  const policy = tmp('allow.txt');
  fs.writeFileSync(policy, 'good.com\nnot a host name\n');
  assert.throws(() => createGate({ policyFile: policy, receiptsFile: tmp('e.jsonl') }), /bad policy line/);
});

test('reload: a good edit takes effect; a malformed edit keeps the last good policy and is receipted', async () => {
  const policy = tmp('allow.txt');
  const receipts = tmp('egress.jsonl');
  fs.writeFileSync(policy, 'one.example\n');
  const g = createGate({ policyFile: policy, receiptsFile: receipts });
  assert.deepEqual(g.rules(), ['one.example']);

  fs.writeFileSync(policy, 'one.example\ntwo.example\n');
  assert.deepEqual(g.reload(), ['one.example', 'two.example']);
  assert.equal(lines(receipts).at(-1).kind, 'policy-reload');

  fs.writeFileSync(policy, 'one.example\nhttp://broken/\n');
  assert.deepEqual(g.reload(), ['one.example', 'two.example'], 'last good policy kept');
  const last = lines(receipts).at(-1);
  assert.equal(last.kind, 'policy-error');
  assert.equal(last.kept_rules, 2);
  g.close();
});

test('watch: an edit to the policy file is picked up without a signal', async () => {
  const policy = tmp('allow.txt');
  fs.writeFileSync(policy, 'one.example\n');
  const g = createGate({ policyFile: policy, receiptsFile: tmp('e.jsonl'), watchMs: 50 });
  await sleep(120); // watchFile needs a baseline stat before it reports a change
  fs.writeFileSync(policy, 'one.example\nthree.example\n');
  for (let i = 0; i < 40 && g.rules().length < 2; i++) await sleep(50);
  assert.deepEqual(g.rules(), ['one.example', 'three.example']);
  g.close();
});

test('plain-http to a blocked host is refused; https-as-plain is refused', async () => {
  const receipts = tmp('egress.jsonl');
  const g = createGate({ rules: ['registry.npmjs.org'], receiptsFile: receipts });
  const gPort = await listen(g.server);
  const get = (url) => new Promise((ok) => http.get({ host: '127.0.0.1', port: gPort, path: url }, (r) => { r.resume(); ok(r); }));
  assert.equal((await get('http://example.com/')).headers['x-gate-reason'], 'not-on-allowlist');
  assert.equal((await get('https://registry.npmjs.org/')).headers['x-gate-reason'], 'scheme');
  g.close();
});

// --- address selection ---------------------------------------------------------------

// A target that only listens on 127.0.0.1, and a gate whose resolver says what we choose.
async function viaResolver(answers, { allowPrivate = true } = {}) {
  const target = http.createServer((q, r) => r.end('hello from target'));
  const tPort = await listen(target);
  const receipts = tmp('egress.jsonl');
  const g = createGate({ rules: ['multi.example'], allowPrivate, receiptsFile: receipts, ports: [tPort], lookup: async () => answers });
  const gPort = await listen(g.server);
  const out = await connectVia(gPort, `multi.example:${tPort}`);
  const done = () => { out.s.destroy(); g.close(); target.close(); };
  return { ...out, receipts, done };
}

test('address selection: IPv4 is tried before IPv6, whatever order DNS answered in', async () => {
  const r = await viaResolver([{ address: '::1', family: 6 }, { address: '127.0.0.1', family: 4 }]);
  assert.match(r.head, /^HTTP\/1\.1 200/);
  assert.equal(lines(r.receipts)[0].ip, '127.0.0.1');
  r.done();
});

test('address selection: when the first address refuses, the next one is tried', async () => {
  // 127.0.0.2 is loopback too, and nothing listens there: instant ECONNREFUSED.
  const r = await viaResolver([{ address: '127.0.0.2', family: 4 }, { address: '127.0.0.1', family: 4 }]);
  assert.match(r.head, /^HTTP\/1\.1 200/);
  r.done();
});

test('address selection: a name with ANY private address is refused, even beside a public one', async () => {
  const r = await viaResolver([{ address: '140.82.112.3', family: 4 }, { address: '10.0.0.5', family: 4 }], { allowPrivate: false });
  assert.match(r.head, /^HTTP\/1\.1 403/);
  assert.match(r.head, /X-Gate-Reason: private-ip/);
  assert.equal(lines(r.receipts)[0].decision, 'deny');
  r.done();
});

test('address selection: an IPv6-only loopback answer is refused as private', async () => {
  const r = await viaResolver([{ address: '::1', family: 6 }], { allowPrivate: false });
  assert.match(r.head, /X-Gate-Reason: private-ip/);
  r.done();
});

test('address selection: a resolver that fails or answers nothing is a 502, never a hang or a bypass', async () => {
  for (const lookup of [async () => { throw new Error('ENOTFOUND'); }, async () => []]) {
    const receipts = tmp('egress.jsonl');
    const g = createGate({ rules: ['multi.example'], receiptsFile: receipts, lookup });
    const gPort = await listen(g.server);
    const { head } = await connectVia(gPort, 'multi.example:443');
    assert.match(head, /^HTTP\/1\.1 502/);
    assert.equal(lines(receipts).at(-1).kind, 'egress-close');
    g.close();
  }
});
