#!/usr/bin/env bash
# vm-shell.sh — open a shell in the sandbox (or run one command) and leave a receipt.
#
#   ./scripts/vm-shell.sh                 interactive bash
#   ./scripts/vm-shell.sh -- npm test     one command (arguments, not a shell line:
#   use `-- bash -c 'a | b'` when you want pipes or globs)
#
# Writes receipts/shell.jsonl, its own hash chain: who, from which machine, when it
# started and ended, the exit code, and for a command the program name and a hash of
# the full command line (the text itself is not kept — command lines can hold secrets).
# Fails closed like the gate: if the start receipt cannot be written, no shell opens.
#
# This is an audit aid, not a wall. Anyone with Docker access can still `docker exec`
# straight into the container and leave no trace here.
set -uo pipefail
cd "$(dirname "$0")/.."
LOG=receipts/shell.jsonl
mkdir -p receipts

if [[ "${1:-}" == "--" ]]; then
  shift
  [[ $# -gt 0 ]] || { echo "vm-shell: nothing to run after --" >&2; exit 2; }
  mode=command; prog="$1"
  # Hash the argument list itself (NUL-separated), not a re-joined string.
  hash="$(printf '%s\0' "$@" | sha256sum | cut -d' ' -f1)"
else
  mode=interactive; prog=bash; hash=""
fi

node scripts/shell-receipt.mjs "$LOG" shell-start mode="$mode" program="$prog" cmd_sha256="$hash" \
  || { echo "vm-shell: refusing to open a shell it cannot record" >&2; exit 1; }

started=$(date +%s); code=0
trap 'node scripts/shell-receipt.mjs "$LOG" shell-end mode="$mode" program="$prog" exit_code="$code" seconds="$(( $(date +%s) - started ))" || echo "vm-shell: WARNING: could not write the shell-end receipt" >&2' EXIT

tty=(); [[ -t 0 ]] || tty=(-T)
if [[ "$mode" == command ]]; then
  # The arguments go through untouched. Re-joining them into one string and handing
  # that to `bash -c` would re-parse the quoting: `-- bash -c 'exit 7'` once came back
  # as exit 0, and the receipt recorded it. Use `-- bash -c '...'` for pipes and globs.
  docker compose exec "${tty[@]}" sandbox "$@" || code=$?
else
  docker compose exec "${tty[@]}" sandbox bash || code=$?
fi
exit "$code"
