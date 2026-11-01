#!/usr/bin/env bash
# vm-check.sh — prove the walls hold, against the running containers.
# Every check is a real attempt from inside the sandbox; exit 1 if any fails.
#   --offline   skip the one check that needs the internet (allowed host works)
set -uo pipefail
cd "$(dirname "$0")/.."
offline=0; [[ "${1:-}" == "--offline" ]] && offline=1

pass=0; fail=0
ok()  { printf '  PASS  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail+1)); }
in_box() { docker compose exec -T sandbox bash -c "$1" 2>&1; }
project="$(docker compose config --format json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).name))')"
probe="probe-$(date +%s)-$RANDOM.example.com"

echo "meshtool-vm check"

# --- the box --------------------------------------------------------------------
out=$(in_box 'id -u'); [[ "$out" == "1000" ]] && ok "agent runs as uid 1000, not root" || bad "agent runs as uid 1000" "id -u -> $out"

out=$(in_box 'grep CapEff /proc/self/status'); [[ "$out" =~ 0000000000000000 ]] && ok "every Linux capability is dropped" || bad "capabilities dropped" "$out"

out=$(in_box 'touch /usr/local/bin/planted && echo WROTE || echo REFUSED'); [[ "$out" == *REFUSED* ]] && ok "system files are read-only" || bad "read-only root" "$out"

out=$(in_box 'touch /work/.vm-check && rm /work/.vm-check && echo OK'); [[ "$out" == *OK* ]] && ok "the workspace /work is writable" || bad "workspace writable" "$out"

out=$(in_box 'grep -q NoNewPrivs:.*1 /proc/self/status && echo SET'); [[ "$out" == *SET* ]] && ok "no-new-privileges is set (setuid cannot escalate)" || bad "no-new-privileges" "$out"

out=$(in_box 'for i in 1 2 3; do setsid bash -c "sleep 0.05 & exit"; done; sleep 0.5; grep -l "^State:.*Z" /proc/[0-9]*/status 2>/dev/null | wc -l')
[[ "$out" == "0" ]] && ok "orphaned processes are reaped (no zombies pile up)" || bad "zombies reaped" "zombies after 3 orphans: $out"

out=$(in_box 'env' | grep -iE '^[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z0-9_]*=' | cut -d= -f1 | tr '\n' ' ')
shapes=$(in_box 'env' | grep -E '(ghp_[A-Za-z0-9]{20}|github_pat_|gho_[A-Za-z0-9]{20}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10}|-----BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.)' | cut -d= -f1 | tr '\n' ' ')
[[ -z "$out$shapes" ]] && ok "no secrets in the sandbox environment (checked by name and by shape)" || bad "no secrets in the sandbox" "named like a secret: ${out:-none}; shaped like one: ${shapes:-none}"

out=$(in_box 'ls /run/relay >/dev/null 2>&1 && echo SEES || echo NO')
[[ "$out" == *NO* ]] && ok "the sandbox cannot see the cloud relay socket" || bad "relay hidden from the sandbox" "$out"

# --- the network ---------------------------------------------------------------------
# Vacuous on a kernel without IPv6 (no /proc/net/if_inet6); real on one that has it.
out=$(in_box 'cat /proc/net/if_inet6 2>/dev/null | grep -vE "^0{31}1 " | grep -vE "^fe80" | wc -l')
[[ "$out" == "0" ]] && ok "the sandbox has no routable IPv6 address" || bad "no IPv6" "addresses: $out"

out=$(in_box 'awk "NR>1 && \$2==\"00000000\"" /proc/net/route | wc -l')
[[ "$out" == "0" ]] && ok "the sandbox has no default route (nowhere to go but the gate)" || bad "no default route" "default routes: $out"

out=$(in_box 'getent hosts gate >/dev/null && echo GATE_OK; getent hosts example.com >/dev/null && echo LEAK || echo BLOCKED')
[[ "$out" == *GATE_OK* && "$out" == *BLOCKED* ]] && ok "DNS resolves the gate only; outside names do not leak" || bad "DNS blocked" "$out"

subnet="$(docker network inspect "${project}_inside" --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)"
host_ip="${subnet%.*/*}.1"
lport=$((20000 + RANDOM % 20000))
node -e "require('http').createServer((q,r)=>r.end('host')).listen($lport,'0.0.0.0')" >/dev/null 2>&1 &
lpid=$!
sleep 0.5
# The listener must be answering on the host before the probe means anything.
if [[ "$(curl -sS --noproxy '*' -m 3 http://127.0.0.1:$lport/ 2>/dev/null)" == "host" ]]; then
  code=$(in_box "curl -s --noproxy '*' -m 4 -o /dev/null -w '%{http_code}' http://$host_ip:$lport/ 2>/dev/null" | tail -1)
  [[ "$code" == "000" ]] && ok "a service listening on the host is unreachable from the sandbox" || bad "host unreachable" "host $host_ip:$lport answered HTTP $code from inside the sandbox"
else
  bad "host unreachable" "could not start a test listener on the host port $lport"
fi
kill $lpid 2>/dev/null

out=$(in_box 'curl -sS --noproxy "*" -m 6 -o /dev/null https://registry.npmjs.org/ && echo REACHED || echo NO_ROUTE')
[[ "$out" == *NO_ROUTE* ]] && ok "bypassing the gate goes nowhere" || bad "no route around the gate" "$out"

# --- the gate --------------------------------------------------------------------------
out=$(in_box "curl -sS -m 8 -o /dev/null -w '%{http_code}' https://$probe/ ; echo")
sleep 0.3
if grep -q "\"host\":\"$probe\".*\"decision\":\"deny\"" receipts/egress.jsonl 2>/dev/null; then
  ok "an unlisted host is blocked, and the block is receipted"
else
  bad "unlisted host blocked + receipted" "curl: $out; no deny receipt for $probe"
fi

out=$(in_box 'curl -sS -m 6 -o /dev/null https://140.82.112.3/ && echo REACHED || echo BLOCKED')
[[ "$out" == *BLOCKED* ]] && ok "raw IP addresses are blocked (policy is by name)" || bad "IP literal blocked" "$out"

if (( offline )); then
  echo "  SKIP  allowed host works (--offline)"
else
  out=$(in_box 'npm view left-pad version 2>&1 | tail -1')
  if [[ "$out" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && grep -q '"host":"registry.npmjs.org".*"decision":"allow"' receipts/egress.jsonl; then
    ok "an allowlisted host works through the gate (npm registry), and is receipted"
  else
    bad "allowlisted host works" "npm view -> $out"
  fi
fi

# --- the audit trail -----------------------------------------------------------------
# Last, so it covers everything above. Read the gate's live head first, then check
# the file: if the tail was cut or a line edited, the live head is no longer in it.
hz=$(in_box 'curl -s --noproxy "*" -m 4 http://gate:3128/healthz')
mb=$(sed -n 's/.*budget_mb=\([0-9]*\).*/\1/p' <<<"$hz")
[[ -n "$mb" && "$mb" -gt 0 ]] && ok "the gate enforces an upload budget ($mb MB per host per hour)" || bad "upload budget on" "/healthz said: $hz"

live=$(sed -n 's/.*head=\([0-9a-f]\{64\}\|genesis\).*/\1/p' <<<"$hz")
if [[ -z "$live" ]]; then
  bad "receipts are an intact hash chain" "could not read the gate's live head from /healthz: $hz"
elif out=$(node scripts/verify-receipts.mjs receipts/egress.jsonl --head "$live" 2>&1); then
  ok "the receipts are an intact hash chain, and match the running gate ($out)"
else
  bad "receipts are an intact hash chain" "$out"
fi

echo "$pass passed, $fail failed"
(( fail == 0 ))
