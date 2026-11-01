// shell-receipt.mjs — append one record to the shell log's hash chain.
//   node scripts/shell-receipt.mjs receipts/shell.jsonl shell-start mode=command program=npm
// key=value pairs; numbers stay numbers. Who and where are added automatically.
// Exits non-zero if the receipt could not be written (vm-shell.sh then refuses to open the shell).
import os from 'node:os';
import { appendChained } from '../gate/gate.mjs';

const [file, kind, ...pairs] = process.argv.slice(2);
if (!file || !kind) { console.error('usage: shell-receipt.mjs <file> <kind> [key=value ...]'); process.exit(2); }

const rec = { kind, user: os.userInfo().username, host: os.hostname() };
for (const p of pairs) {
  const i = p.indexOf('=');
  if (i < 1) { console.error(`bad pair: ${p}`); process.exit(2); }
  const v = p.slice(i + 1);
  rec[p.slice(0, i)] = v !== '' && /^-?\d+(\.\d+)?$/.test(v) ? Number(v) : v;
}
try { appendChained(file, rec); } catch (e) { console.error(`cannot write ${file}: ${e.message}`); process.exit(1); }
