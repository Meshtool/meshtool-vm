// gate.mjs — the sandbox's only way out. Zero dependencies.
//
// The sandbox container sits on a network with no route anywhere except this
// gate. Every outbound connection is a decision against policy/allow.txt, and
// every decision — allowed or blocked — becomes one JSON line in the receipts
// file. Fail closed throughout:
//   - no policy file, or an empty one      -> everything is blocked
//   - a bad policy line at start           -> the gate refuses to start
//   - a bad policy line on reload          -> last good policy stays, receipted
//   - an IP literal, an odd port           -> blocked (policy is by name)
//   - an allowed name that resolves to a   -> blocked (the policy names public
//     loopback / LAN / link-local address     services, never the host or LAN)
//   - a host past its upload budget        -> blocked, tunnel cut, receipted
//   - the receipt cannot be written        -> blocked (no audit, no exit)
//
// Receipts are hash-chained: every line carries `prev`, the sha256 of the line
// before it, so an edit, a deletion or a reorder anywhere in the middle of the
// file is detectable (scripts/verify-receipts.mjs). The head hash is also
// served at /healthz, which catches a truncated tail while the gate is up.

import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const RULE = /^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const GENESIS = 'genesis';

export const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function parsePolicy(text) {
  const rules = [];
  for (const raw of String(text).split('\n')) {
    const line = raw.replace(/#.*/, '').trim().toLowerCase();
    if (!line) continue;
    if (!RULE.test(line)) throw new Error(`bad policy line: ${JSON.stringify(raw)}`);
    rules.push(line);
  }
  return rules;
}

// Missing file -> no rules (blocks everything). Malformed file -> throws.
export function readPolicy(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return { rules: [], sha256: 'missing' }; }
  return { rules: parsePolicy(text), sha256: sha256Hex(text) };
}
export const loadPolicy = (file) => readPolicy(file).rules;

export function decide(rules, rawHost, port, ports = [80, 443]) {
  const host = String(rawHost || '').toLowerCase().replace(/\.$/, '');
  if (!HOST.test(host)) return { allow: false, reason: 'bad-host', host };
  if (net.isIP(host) || /^[0-9.]+$/.test(host)) return { allow: false, reason: 'ip-literal', host };
  if (!ports.includes(Number(port))) return { allow: false, reason: 'port', host };
  if (!rules.length) return { allow: false, reason: 'no-policy', host };
  for (const r of rules) {
    if (r === host) return { allow: true, reason: `rule:${r}`, host };
    if (r.startsWith('*.') && host.endsWith(r.slice(1))) return { allow: true, reason: `rule:${r}`, host };
  }
  return { allow: false, reason: 'not-on-allowlist', host };
}

// Addresses that are never a public service: the host itself, the LAN,
// link-local, multicast, reserved. An allowlisted name pointing here is a
// trick (or a misconfiguration), and either way it is refused.
export function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIP(mapped[1]);
    return v === '::' || v === '::1' || /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || v.startsWith('ff');
  }
  return true; // not an IP at all: refuse
}

// --- the receipt chain ------------------------------------------------------------

// Verify a receipts file's text. Hashes the raw line text (no re-serialising),
// so there is no canonical-JSON question. `hashes` lists the hash of every line,
// so a caller holding the gate's live head can prove the tail was not cut.
export function verifyChain(text) {
  const body = text.endsWith('\n') ? text.slice(0, -1) : text;
  if (body === '') return { ok: true, count: 0, head: GENESIS, hashes: [] };
  const lines = body.split('\n');
  const hashes = [];
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let obj;
    try { obj = JSON.parse(lines[i]); } catch { return { ok: false, line: i + 1, error: 'not valid JSON' }; }
    if (obj.prev !== prev) {
      return { ok: false, line: i + 1, error: i === 0 ? 'first line does not start the chain' : 'chain broken: a line before this one was edited, removed or reordered' };
    }
    prev = sha256Hex(lines[i]);
    hashes.push(prev);
  }
  return { ok: true, count: lines.length, head: prev, hashes };
}

// Pick the chain back up from the end of an existing file after a restart.
function readHead(file) {
  try {
    const fd = fs.openSync(file, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      if (!size) return GENESIS;
      const len = Math.min(size, 65536);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, size - len);
      const last = buf.toString('utf8').split('\n').filter(Boolean).pop();
      return last ? sha256Hex(last) : GENESIS;
    } finally { fs.closeSync(fd); }
  } catch { return GENESIS; }
}

// Append one record to a chained receipts file other than the gate's own (the shell
// log). The gate is the only writer of its file and keeps its head in memory; these
// files have several short-lived writers, so a directory lock keeps two of them from
// forking the chain. A lock older than 10 s is taken to be a crashed writer's.
export function appendChained(file, record, { lockWaitMs = 3000 } = {}) {
  const lock = `${file}.lock`;
  const deadline = Date.now() + lockWaitMs;
  for (;;) {
    try { fs.mkdirSync(lock); break; } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > 10_000) fs.rmdirSync(lock); } catch { /* raced: fine */ }
      if (Date.now() > deadline) throw new Error('receipt lock busy');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20); // sleep 20 ms
    }
  }
  try {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...record, prev: readHead(file) });
    fs.appendFileSync(file, line + '\n');
    return sha256Hex(line);
  } finally { try { fs.rmdirSync(lock); } catch { /* already gone */ } }
}

// --- upstream proxy (cloud mode) --------------------------------------------------

// "unix:/path" is a unix socket (no network exposure at all); anything else is
// an http://host:port proxy.
function parseUpstream(u) {
  if (!u) return null;
  if (u.startsWith('unix:')) return { socketPath: u.slice(5) };
  const x = new URL(u); // throws on junk: the gate refuses to start
  return { host: x.hostname, port: Number(x.port) || 80 };
}

function splitHostPort(s, defPort) {
  const i = s.lastIndexOf(':');
  if (i <= 0) return [s, defPort];
  return [s.slice(0, i), Number(s.slice(i + 1))];
}

// Open a TCP stream to target:port, directly or through an upstream CONNECT proxy.
function dial(target, port, up, cb) {
  let s, fired = false;
  const done = (err, sock, head) => {
    if (fired) return; fired = true; clearTimeout(t);
    if (err) s?.destroy();
    cb(err, sock, head);
  };
  const t = setTimeout(() => done(new Error('connect-timeout')), 10_000);
  if (!up) {
    s = net.connect(port, target, () => done(null, s, Buffer.alloc(0)));
    s.once('error', (e) => done(e));
    return;
  }
  const hello = () => s.write(`CONNECT ${target}:${port} HTTP/1.1\r\nHost: ${target}:${port}\r\n\r\n`);
  s = up.socketPath ? net.connect({ path: up.socketPath }, hello) : net.connect(up.port, up.host, hello);
  let buf = Buffer.alloc(0);
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    const end = buf.indexOf('\r\n\r\n');
    if (end < 0) { if (buf.length > 16384) done(new Error('upstream-bad-reply')); return; }
    s.off('data', onData);
    const status = Number(buf.subarray(0, end).toString().split(' ')[1]);
    if (status !== 200) return done(new Error(`upstream-${status}`));
    done(null, s, buf.subarray(end + 4));
  };
  s.on('data', onData);
  s.once('error', (e) => done(e));
}

// Try each candidate address in turn (IPv4 first), so one dead address — say an AAAA
// record on a host with no IPv6 route — does not fail a name whose A record works.
function dialAny(targets, port, up, cb) {
  const list = targets.slice(0, 3);
  let i = 0, lastErr;
  const next = () => {
    if (i >= list.length) return cb(lastErr || new Error('no-address'));
    dial(list[i++], port, up, (err, sock, head) => { if (err) { lastErr = err; return next(); } cb(null, sock, head); });
  };
  next();
}

export function createGate({
  policyFile, rules: fixed, receiptsFile, ports = [80, 443], upstream = '',
  allowPrivate = false, watchMs = 0, maxConnections = 256,
  uploadBudget = 0, budgetWindowMs = 3_600_000, log = () => {},
  // DNS, injectable so tests do not depend on the machine's resolver. Must return
  // [{ address, family }, ...] — every record, not just the first.
  lookup = (host) => dns.promises.lookup(host, { all: true, verbatim: true }),
} = {}) {
  const up = parseUpstream(upstream);

  // Throws on a malformed policy: at start, that refuses to start (see main).
  let policy = fixed ? { rules: fixed, sha256: sha256Hex(fixed.join('\n')) } : readPolicy(policyFile);
  const rules = () => policy.rules;

  // --- receipts: chained, and a receipt that cannot be written means the action does not happen.
  let head = readHead(receiptsFile);
  const receipt = (r) => {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...r, prev: head });
    fs.appendFileSync(receiptsFile, line + '\n');
    head = sha256Hex(line); // advance only once the line is on disk
    log(line);
  };
  const tryReceipt = (r) => { try { receipt(r); return true; } catch { return false; } };

  // Can a receipt be written right now? When it cannot, the gate refuses everything
  // (fail closed) — so /healthz must say so, or it looks healthy while blocking all.
  const canWrite = () => {
    try { fs.accessSync(fs.existsSync(receiptsFile) ? receiptsFile : path.dirname(receiptsFile), fs.constants.W_OK); return true; }
    catch { return false; }
  };

  // On reload, a malformed policy keeps the last good one and says so, so a
  // half-saved edit does not black-hole the sandbox mid-task.
  const reload = () => {
    if (fixed) return policy.rules;
    try {
      policy = readPolicy(policyFile);
      tryReceipt({ kind: 'policy-reload', rules: policy.rules.length, policy_sha256: policy.sha256 });
    } catch (e) {
      tryReceipt({ kind: 'policy-error', error: e.message, kept_rules: policy.rules.length, policy_sha256: policy.sha256 });
    }
    return policy.rules;
  };
  if (watchMs > 0 && policyFile) fs.watchFile(policyFile, { interval: watchMs }, reload);

  // The first receipt of a run: which policy, exactly, this gate is enforcing.
  const announce = () => tryReceipt({
    kind: 'gate-start', rules: policy.rules.length, policy_sha256: policy.sha256,
    upload_budget_bytes: uploadBudget, upstream: up ? (up.socketPath ? 'unix' : 'http') : 'none',
  });

  // --- upload budget: bytes sent TO a host per window. Downloads are not limited;
  // the worry is bulk data leaving through a name that is allowed.
  const usage = new Map();
  const charge = (host, n) => {
    if (!uploadBudget) return true;
    const now = Date.now();
    let u = usage.get(host);
    if (!u || now - u.start > budgetWindowMs) { u = { start: now, bytes: 0 }; usage.set(host, u); }
    u.bytes += n;
    return u.bytes <= uploadBudget;
  };
  const overBudget = (host) => {
    if (!uploadBudget) return false;
    const u = usage.get(host);
    return !!u && Date.now() - u.start <= budgetWindowMs && u.bytes >= uploadBudget;
  };
  const budgetReceipt = (host, port) => tryReceipt({
    kind: 'budget-exceeded', host, port, budget_bytes: uploadBudget, window_ms: budgetWindowMs,
  });

  // In direct mode the gate resolves the name itself and refuses private
  // addresses. Behind an upstream proxy, that proxy resolves and connects.
  // Every record is checked: a name with one public and one private address is refused,
  // so a mixed answer cannot smuggle the private one in. The gate connects only to
  // addresses it has just validated (never re-resolving), IPv4 first.
  const resolve = async (host) => {
    if (up) return { targets: [host] };
    const addrs = await lookup(host);
    if (!addrs?.length) throw new Error('no-address');
    if (!allowPrivate) {
      const bad = addrs.find((a) => isPrivateIP(a.address));
      if (bad) return { error: 'private-ip', ip: bad.address };
    }
    const ordered = [...addrs].sort((a, b) => a.family - b.family);
    return { targets: ordered.map((a) => a.address), ip: ordered[0].address };
  };

  const server = http.createServer(async (req, res) => {
    if (req.url === '/healthz') {
      if (!canWrite()) {
        res.writeHead(503, { 'content-type': 'text/plain' });
        return res.end('receipts-unwritable: the gate cannot write its receipts, so it refuses every connection\n');
      }
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end(`ok rules=${policy.rules.length} head=${head} budget_mb=${Math.round(uploadBudget / 1048576)}\n`);
    }
    let url;
    try { url = new URL(req.url); } catch { res.writeHead(400); return res.end('not a proxy request\n'); }
    const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
    const d = decide(policy.rules, url.hostname, port, ports);
    const refuse = (reason) => {
      const wrote = tryReceipt({ kind: 'egress', method: req.method, host: d.host, port, decision: 'deny', reason });
      reason = wrote ? reason : 'receipt-unwritable';
      res.writeHead(403, { 'x-gate-reason': reason }); res.end(`blocked by gate: ${reason}\n`);
    };
    if (!d.allow) return refuse(d.reason);
    if (url.protocol !== 'http:') return refuse('scheme');
    let r;
    try { r = await resolve(d.host); } catch { res.writeHead(502); return res.end(); }
    if (r.error) return refuse(r.error);
    if (overBudget(d.host)) return refuse('upload-budget');
    if (!tryReceipt({ kind: 'egress', method: req.method, host: d.host, port, ip: r.ip, decision: 'allow', reason: d.reason })) {
      res.writeHead(403, { 'x-gate-reason': 'receipt-unwritable' }); return res.end('blocked by gate: receipt-unwritable\n');
    }
    const opts = {
      method: req.method, headers: { ...req.headers, host: url.host },
      ...(up
        ? { ...(up.socketPath ? { socketPath: up.socketPath } : { host: up.host, port: up.port }), path: req.url }
        : { host: r.targets[0], port, path: url.pathname + url.search }),
    };
    const fwd = http.request(opts, (resp) => { res.writeHead(resp.statusCode, resp.headers); resp.pipe(res); });
    fwd.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.on('data', (b) => {
      if (charge(d.host, b.length)) return;
      budgetReceipt(d.host, port);
      req.destroy(); fwd.destroy();
    });
    req.pipe(fwd);
  });

  server.on('connect', async (req, client, head0) => {
    client.on('error', () => {});
    const started = Date.now();
    const [rawHost, port] = splitHostPort(req.url, 443);
    const d = decide(policy.rules, rawHost, port, ports);
    const refuse = (reason) => {
      const wrote = tryReceipt({ kind: 'egress', method: 'CONNECT', host: d.host, port, decision: 'deny', reason });
      reason = wrote ? reason : 'receipt-unwritable';
      client.end(`HTTP/1.1 403 Forbidden\r\nX-Gate-Reason: ${reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    };
    const fail = (err) => {
      tryReceipt({ kind: 'egress-close', host: d.host, port, error: err.message, ms: Date.now() - started });
      client.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
    };
    if (!d.allow) return refuse(d.reason);
    let r;
    try { r = await resolve(d.host); } catch (e) { return fail(e); }
    if (r.error) return refuse(r.error);
    if (overBudget(d.host)) return refuse('upload-budget');
    if (!tryReceipt({ kind: 'egress', method: 'CONNECT', host: d.host, port, ip: r.ip, decision: 'allow', reason: d.reason })) {
      return refuse('receipt-unwritable');
    }
    dialAny(r.targets, port, up, (err, sock, extra) => {
      if (err) return fail(err);
      let sent = 0, recv = 0, closed = false;
      const close = () => {
        if (closed) return; closed = true;
        client.destroy(); sock.destroy();
        tryReceipt({ kind: 'egress-close', host: d.host, port, bytes_up: sent, bytes_down: recv, ms: Date.now() - started });
      };
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (extra.length) { recv += extra.length; client.write(extra); }
      if (head0.length) {
        sent += head0.length; sock.write(head0);
        if (!charge(d.host, head0.length)) { budgetReceipt(d.host, port); return close(); }
      }
      client.on('data', (b) => {
        sent += b.length;
        if (!charge(d.host, b.length)) { budgetReceipt(d.host, port); close(); }
      });
      sock.on('data', (b) => { recv += b.length; });
      client.pipe(sock); sock.pipe(client);
      sock.setTimeout(300_000, () => sock.destroy());
      sock.on('close', close); client.on('close', close);
      sock.on('error', close);
    });
  });

  // A runaway sandbox cannot exhaust the gate: past this, new connections are dropped.
  server.maxConnections = maxConnections;

  const close = () => { if (watchMs > 0 && policyFile) fs.unwatchFile(policyFile, reload); server.close(); };
  return { server, reload, close, announce, rules, head: () => head };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const env = process.env;
  let gate;
  try {
    gate = createGate({
      policyFile: env.POLICY_FILE || '/policy/allow.txt',
      receiptsFile: env.RECEIPTS_FILE || '/receipts/egress.jsonl',
      ports: (env.GATE_PORTS || '80,443').split(',').map(Number),
      upstream: env.UPSTREAM_PROXY || '',
      allowPrivate: env.GATE_ALLOW_PRIVATE === '1',
      watchMs: Number(env.POLICY_WATCH_MS ?? 2000),
      maxConnections: Number(env.GATE_MAX_CONNECTIONS || 256),
      uploadBudget: Math.round(Number(env.GATE_UPLOAD_BUDGET_MB || 0) * 1048576),
      budgetWindowMs: Number(env.GATE_BUDGET_WINDOW_MIN || 60) * 60_000,
      log: (l) => console.log(l),
    });
  } catch (e) {
    console.error(`gate: refusing to start: ${e.message}`);
    process.exit(1);
  }
  if (!gate.rules().length) console.warn('gate: policy is empty or missing — every connection will be blocked');
  if (!gate.announce()) {
    console.error(`gate: CANNOT WRITE RECEIPTS to ${env.RECEIPTS_FILE || '/receipts/egress.jsonl'} — every connection will be refused until this is fixed. `
      + 'The gate runs as uid 1000: check that the receipts folder and file are writable by it (scripts/vm-up.sh repairs this).');
  }
  process.on('SIGHUP', () => console.log(`gate: policy reloaded, ${gate.reload().length} rules`));
  const port = Number(env.GATE_LISTEN || 3128);
  gate.server.listen(port, '0.0.0.0', () => console.log(`gate: listening on :${port}, ${gate.rules().length} rules`));
}
