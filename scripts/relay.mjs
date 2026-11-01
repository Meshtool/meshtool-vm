// relay.mjs — plain TCP forwarder: LISTEN_HOST:LISTEN_PORT -> TARGET_HOST:TARGET_PORT.
// Used only in cloud mode, so the gate container can reach a proxy that the host
// binds to 127.0.0.1. It forwards bytes; every decision is still the gate's.
// Usage: node relay.mjs <listen-host> <listen-port> <target-host> <target-port>
import net from 'node:net';

const [lh, lp, th, tp] = process.argv.slice(2);
if (!lh || !lp || !th || !tp) { console.error('usage: relay.mjs <listen-host> <listen-port> <target-host> <target-port>'); process.exit(2); }

net.createServer((c) => {
  const u = net.connect(Number(tp), th);
  c.pipe(u); u.pipe(c);
  const end = () => { c.destroy(); u.destroy(); };
  c.on('error', end); u.on('error', end); c.on('close', end); u.on('close', end);
}).listen(Number(lp), lh, () => console.log(`relay: ${lh}:${lp} -> ${th}:${tp}`));
