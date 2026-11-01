#!/usr/bin/env bash
# vm-up.sh — one command: Docker answering, folders ready, gate + sandbox running.
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/docker-up.sh
mkdir -p receipts work
# The gate and the sandbox run as uid 1000; let them write their folders.
chmod a+rwx receipts work
docker compose up -d --build --wait
echo "vm-up: running. Get a shell:  docker compose exec sandbox bash"
echo "vm-up: receipts:              tail -f receipts/egress.jsonl"
