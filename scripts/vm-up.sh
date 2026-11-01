#!/usr/bin/env bash
# vm-up.sh — one command: Docker answering, folders ready, gate + sandbox running.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/docker-up.sh
mkdir -p receipts work
# Receipts written before the hash chain existed cannot be verified. Keep them,
# but start a clean chain so vm-check means something.
if [[ -s receipts/egress.jsonl ]] && ! head -1 receipts/egress.jsonl | grep -q '"prev"'; then
  mv receipts/egress.jsonl "receipts/egress.unchained-$(date +%Y%m%d-%H%M%S).jsonl"
  echo "vm-up: moved an unchained receipts file aside; starting a fresh chain"
fi
# The gate and the sandbox run as uid 1000; let them write their folders. A receipts
# file left behind by another user (say, root) would make the gate refuse everything.
chmod a+rwx receipts work
if [[ -f receipts/egress.jsonl ]]; then
  if [[ "$(id -u)" == 0 ]]; then chown 1000:1000 receipts/egress.jsonl; chmod 644 receipts/egress.jsonl
  else chmod a+rw receipts/egress.jsonl; fi
fi
# A gate that was unhealthy before the repairs above keeps that status until it is
# restarted, and `up --wait` judges the stale status instantly. Give it a fresh start.
gate_id="$(docker compose ps -q gate 2>/dev/null || true)"
if [[ -n "$gate_id" && "$(docker inspect -f '{{.State.Health.Status}}' "$gate_id" 2>/dev/null)" == unhealthy ]]; then
  echo "vm-up: the gate was unhealthy; restarting it now that its folders are repaired"
  docker compose restart gate >/dev/null
fi
if ! docker compose up -d --build --wait; then
  echo "vm-up: the stack did not come up healthy. Gate log:" >&2
  docker compose logs --tail 15 gate >&2 || true
  echo "vm-up: if the build said '429 Too Many Requests', Docker Hub is rate-limiting the base image:" >&2
  echo "vm-up:   wait a few minutes and re-run, or 'docker login'. (It will not run stale images for you:" >&2
  echo "vm-up:   the gate is security code, so a build that did not happen is a failure, not a fallback.)" >&2
  exit 1
fi
echo "vm-up: running. Get a shell:  docker compose exec sandbox bash"
echo "vm-up: receipts:              tail -f receipts/egress.jsonl"
echo "vm-up: verify the receipts:   node scripts/verify-receipts.mjs receipts/egress.jsonl"
