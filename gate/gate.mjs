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
//   - the receipt cannot be written        -> blocked (no audit, no exit)

import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const RULE = /^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const HOST = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

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

// Missing file -> [] (blocks everything). Malformed file -> throws.
export function loadPolicy(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return []; }
  return parsePolicy(text);
}

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

function splitHostPort(s, defPort) {
  const i = s.lastIndexOf(':');
  if (i <= 0) return [s, defPort];
  return [s.slice(0, i), Number(s.slice(i + 1))];
}

// Open a TCP stream to target:port, directly or through an upstream CONNECT proxy.
function dial(target, port, upstream, cb) {
  let s, fired = false;
  const done = (err, sock, head) => {
    if (fired) return; fired = true; clearTimeout(t);
    if (err) s?.destroy();
    cb(err, sock, head);
  };
  const t = setTimeout(() => done(new Error('connect-timeout')), 10_000);
  if (!upstream) {
    s = net.connect(port, target, () => done(null, s, Buffer.alloc(0)));
    s.once('error', (e) => done(e));
    return;
  }
  const u = new URL(upstream);
  s = net.connect(Number(u.port) || 80, u.hostname, () => {
    s.write(`CONNECT ${target}:${port} HTTP/1.1\r\nHost: ${target}:${port}\r\n\r\n`);
  });
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

export function createGate({
  policyFile, rules: fixed, receiptsFile, ports = [80, 443], upstream = '',
  allowPrivate = false, watchMs = 0, maxConnections = 256, log = () => {},
} = {}) {
  // Throws on a malformed policy: at start, that refuses to start (see main).
  let rules = fixed ?? loadPolicy(policyFile);

  // A receipt that cannot be written means the action does not happen.
  const receipt = (r) => {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...r }) + '\n';
    fs.appendFileSync(receiptsFile, line);
    log(line.trimEnd());
  };
  const tryReceipt = (r) => { try { receipt(r); return true; } catch { return false; } };

  // On reload, a malformed policy keeps the last good one and says so, so a
  // half-saved edit does not black-hole the sandbox mid-task.
  const reload = () => {
    if (fixed) return rules;
    try {
      rules = loadPolicy(policyFile);
      tryReceipt({ kind: 'policy-reload', rules: rules.length });
    } catch (e) {
      tryReceipt({ kind: 'policy-error', error: e.message, kept_rules: rules.length });
    }
    return rules;
  };
  if (watchMs > 0 && policyFile) fs.watchFile(policyFile, { interval: watchMs }, reload);

  // In direct mode the gate resolves the name itself and refuses private
  // addresses. Behind an upstream proxy, that proxy resolves and connects.
  const resolve = async (host) => {
    if (upstream) return { target: host };
    const { address } = await dns.promises.lookup(host);
    if (!allowPrivate && isPrivateIP(address)) return { error: 'private-ip', ip: address };
    return { target: address, ip: address };
  };

  const server = http.createServer(async (req, res) => {
    if (req.url === '/healthz') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(`ok rules=${rules.length}\n`); }
    let url;
    try { url = new URL(req.url); } catch { res.writeHead(400); return res.end('not a proxy request\n'); }
    const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
    const refuse = (reason) => {
      const wrote = tryReceipt({ kind: 'egress', method: req.method, host: d.host, port, decision: 'deny', reason });
      reason = wrote ? reason : 'receipt-unwritable';
      res.writeHead(403, { 'x-gate-reason': reason }); res.end(`blocked by gate: ${reason}\n`);
    };
    const d = decide(rules, url.hostname, port, ports);
    if (!d.allow) return refuse(d.reason);
    if (url.protocol !== 'http:') return refuse('scheme');
    let r;
    try { r = await resolve(d.host); } catch { res.writeHead(502); return res.end(); }
    if (r.error) return refuse(r.error);
    if (!tryReceipt({ kind: 'egress', method: req.method, host: d.host, port, ip: r.ip, decision: 'allow', reason: d.reason })) {
      res.writeHead(403, { 'x-gate-reason': 'receipt-unwritable' }); return res.end('blocked by gate: receipt-unwritable\n');
    }
    const u = upstream ? new URL(upstream) : null;
    const fwd = http.request({
      host: u ? u.hostname : r.target, port: u ? Number(u.port) || 80 : port,
      method: req.method, path: u ? req.url : url.pathname + url.search,
      headers: { ...req.headers, host: url.host },
    }, (up) => { res.writeHead(up.statusCode, up.headers); up.pipe(res); });
    fwd.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(fwd);
  });

  server.on('connect', async (req, client, head) => {
    client.on('error', () => {});
    const started = Date.now();
    const [rawHost, port] = splitHostPort(req.url, 443);
    const d = decide(rules, rawHost, port, ports);
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
    if (!tryReceipt({ kind: 'egress', method: 'CONNECT', host: d.host, port, ip: r.ip, decision: 'allow', reason: d.reason })) {
      return refuse('receipt-unwritable');
    }
    dial(r.target, port, upstream, (err, sock, extra) => {
      if (err) return fail(err);
      let up = 0, down = 0;
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (extra.length) { down += extra.length; client.write(extra); }
      if (head.length) { up += head.length; sock.write(head); }
      client.on('data', (b) => { up += b.length; });
      sock.on('data', (b) => { down += b.length; });
      client.pipe(sock); sock.pipe(client);
      sock.setTimeout(300_000, () => sock.destroy());
      let closed = false;
      const close = () => {
        if (closed) return; closed = true;
        client.destroy(); sock.destroy();
        tryReceipt({ kind: 'egress-close', host: d.host, port, bytes_up: up, bytes_down: down, ms: Date.now() - started });
      };
      sock.on('close', close); client.on('close', close);
      sock.on('error', close);
    });
  });

  // A runaway sandbox cannot exhaust the gate: past this, new connections are dropped.
  server.maxConnections = maxConnections;

  const close = () => { if (watchMs > 0 && policyFile) fs.unwatchFile(policyFile, reload); server.close(); };
  return { server, reload, close, rules: () => rules };
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
      log: (l) => console.log(l),
    });
  } catch (e) {
    console.error(`gate: refusing to start: ${e.message}`);
    process.exit(1);
  }
  if (!gate.rules().length) console.warn('gate: policy is empty or missing — every connection will be blocked');
  process.on('SIGHUP', () => console.log(`gate: policy reloaded, ${gate.reload().length} rules`));
  const port = Number(env.GATE_LISTEN || 3128);
  gate.server.listen(port, '0.0.0.0', () => console.log(`gate: listening on :${port}, ${gate.rules().length} rules`));
}
