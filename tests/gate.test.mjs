// Run: node --test tests/   (zero deps, no Docker needed)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parsePolicy, decide, createGate } from '../gate/gate.mjs';

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

// --- the real server, in process ---------------------------------------------------

function tmpReceipts() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-'));
  return path.join(dir, 'egress.jsonl');
}
const listen = (srv) => new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok(srv.address().port)));
const lines = (f) => fs.readFileSync(f, 'utf8').trim().split('\n').map((l) => JSON.parse(l));

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

test('allowed CONNECT tunnels and leaves allow + close receipts', async () => {
  const target = http.createServer((q, r) => r.end('hello from target'));
  const tPort = await listen(target);
  const receipts = tmpReceipts();
  const g = createGate({ rules: ['localhost'], receiptsFile: receipts, ports: [tPort] });
  const gPort = await listen(g.server);

  const { s, head } = await connectVia(gPort, `localhost:${tPort}`);
  assert.match(head, /^HTTP\/1\.1 200/);
  s.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  const body = await new Promise((ok) => { let b = ''; s.on('data', (d) => (b += d)); s.on('end', () => ok(b)); });
  assert.match(body, /hello from target/);
  await new Promise((ok) => setTimeout(ok, 50));

  const rs = lines(receipts);
  assert.equal(rs[0].decision, 'allow');
  assert.equal(rs[0].host, 'localhost');
  assert.equal(rs.at(-1).kind, 'egress-close');
  assert.ok(rs.at(-1).bytes_down > 0);
  g.server.close(); target.close();
});

test('blocked CONNECT gets 403 with a reason, and a deny receipt', async () => {
  const receipts = tmpReceipts();
  const g = createGate({ rules: ['localhost'], receiptsFile: receipts });
  const gPort = await listen(g.server);
  const { head } = await connectVia(gPort, 'example.com:443');
  assert.match(head, /^HTTP\/1\.1 403/);
  assert.match(head, /X-Gate-Reason: not-on-allowlist/);
  assert.deepEqual(
    (({ decision, host, reason }) => ({ decision, host, reason }))(lines(receipts)[0]),
    { decision: 'deny', host: 'example.com', reason: 'not-on-allowlist' },
  );
  g.server.close();
});

test('FAIL CLOSED: an unwritable receipts file blocks even an allowed host', async () => {
  const target = http.createServer((q, r) => r.end('should never be reached'));
  const tPort = await listen(target);
  let reached = false; target.on('connection', () => (reached = true));
  const g = createGate({ rules: ['localhost'], receiptsFile: '/nonexistent-dir/egress.jsonl', ports: [tPort] });
  const gPort = await listen(g.server);
  const { head } = await connectVia(gPort, `localhost:${tPort}`);
  assert.match(head, /^HTTP\/1\.1 403/);
  assert.match(head, /receipt-unwritable/);
  assert.equal(reached, false);
  g.server.close(); target.close();
});

test('FAIL CLOSED: a missing policy file blocks everything', async () => {
  const receipts = tmpReceipts();
  const g = createGate({ policyFile: '/nonexistent/allow.txt', receiptsFile: receipts });
  const gPort = await listen(g.server);
  const { head } = await connectVia(gPort, 'registry.npmjs.org:443');
  assert.match(head, /X-Gate-Reason: no-policy/);
  g.server.close();
});

test('plain-http to a blocked host is refused; https-as-plain is refused', async () => {
  const receipts = tmpReceipts();
  const g = createGate({ rules: ['registry.npmjs.org'], receiptsFile: receipts });
  const gPort = await listen(g.server);
  const get = (url) => new Promise((ok) => http.get({ host: '127.0.0.1', port: gPort, path: url }, (r) => { r.resume(); ok(r); }));
  assert.equal((await get('http://example.com/')).headers['x-gate-reason'], 'not-on-allowlist');
  assert.equal((await get('https://registry.npmjs.org/')).headers['x-gate-reason'], 'scheme');
  g.server.close();
});
