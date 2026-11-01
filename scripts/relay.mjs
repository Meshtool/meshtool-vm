// relay.mjs — plain forwarder: a UNIX SOCKET -> a TCP host:port.
// Used only in cloud mode, so the gate container can reach a proxy that the host
// binds to 127.0.0.1. It forwards bytes; every decision is still the gate's.
//
// A socket, not a network port: nothing on any Docker network can reach it. Only
// a container that mounts its directory can, and only the gate does. Where we are
// root the socket is handed to uid 1000 (the gate's user) with mode 0600, so even
// other processes on this machine cannot use it; where we are not, it falls back
// to 0666 and says so.
//
// Usage: node relay.mjs <socket-path> <target-host> <target-port>
import net from 'node:net';
import fs from 'node:fs';

const [sock, th, tp] = process.argv.slice(2);
if (!sock || !th || !tp) { console.error('usage: relay.mjs <socket-path> <target-host> <target-port>'); process.exit(2); }

try { fs.unlinkSync(sock); } catch { /* no stale socket */ }

net.createServer((c) => {
  const u = net.connect(Number(tp), th);
  c.pipe(u); u.pipe(c);
  const end = () => { c.destroy(); u.destroy(); };
  c.on('error', end); u.on('error', end); c.on('close', end); u.on('close', end);
}).listen(sock, () => {
  try {
    fs.chownSync(sock, 1000, 1000);
    fs.chmodSync(sock, 0o600);
    console.log(`relay: ${sock} (owner uid 1000, 0600) -> ${th}:${tp}`);
  } catch {
    fs.chmodSync(sock, 0o666);
    console.warn(`relay: ${sock} (not root, so mode 0666: any local user can use it) -> ${th}:${tp}`);
  }
});
