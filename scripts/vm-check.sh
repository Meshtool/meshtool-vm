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

# --- the network ---------------------------------------------------------------------
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

echo "$pass passed, $fail failed"
(( fail == 0 ))
