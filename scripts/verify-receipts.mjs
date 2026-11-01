// verify-receipts.mjs — is the receipts file still the one the gate wrote?
//
//   node scripts/verify-receipts.mjs receipts/egress.jsonl
//   node scripts/verify-receipts.mjs receipts/egress.jsonl --head <hash from the gate's /healthz>
//
// Exit 0: chain intact (and, with --head, the gate's live head is in the file,
// so the tail was not cut). Exit 1: broken, with the first bad line. Exit 2: usage.
//
// What this proves: an edit, deletion or reorder anywhere in the middle shows up.
// What it cannot: someone who deletes the whole file, or rewrites every line and
// recomputes every hash, while the gate is down. --head against a running gate
// narrows that; keeping a copy off the machine closes it.
import fs from 'node:fs';
import { verifyChain } from '../gate/gate.mjs';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--') && args[args.indexOf(a) - 1] !== '--head');
const hi = args.indexOf('--head');
const wantHead = hi >= 0 ? args[hi + 1] : '';
if (!file || (hi >= 0 && !wantHead)) {
  console.error('usage: verify-receipts.mjs <receipts.jsonl> [--head <hash>]');
  process.exit(2);
}

let text;
try { text = fs.readFileSync(file, 'utf8'); } catch (e) { console.error(`cannot read ${file}: ${e.code}`); process.exit(2); }

const r = verifyChain(text);
if (!r.ok) { console.error(`BROKEN at line ${r.line}: ${r.error}`); process.exit(1); }
if (wantHead && wantHead !== 'genesis' && !r.hashes.includes(wantHead)) {
  console.error(`BROKEN: the gate's live head ${wantHead.slice(0, 12)} is not in the file — the tail was cut or the file was replaced`);
  process.exit(1);
}
console.log(`ok: ${r.count} receipts, chain intact, head ${r.head.slice(0, 12)}${wantHead ? ' (matches the live gate)' : ''}`);
