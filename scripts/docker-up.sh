#!/usr/bin/env bash
# docker-up.sh — make sure a Docker daemon is answering, starting one if needed.
# Idempotent: safe to run on every session start or from a setup script.
#
# On a host whose only way out is a 127.0.0.1 HTTPS proxy (a cloud agent
# container), it also turns on cloud mode: a relay so containers can reach that
# proxy, and a .env that layers compose.cloud.yaml on top of compose.yaml.
set -euo pipefail
cd "$(dirname "$0")/.."
LOG_DIR="${DOCKER_UP_LOG_DIR:-/tmp/meshtool-vm}"
mkdir -p "$LOG_DIR"

say() { printf 'docker-up: %s\n' "$*"; }

if ! command -v docker >/dev/null 2>&1; then
  say "docker is not installed. Install Docker Engine (Linux) or Docker Desktop (Windows/macOS), then re-run."
  exit 1
fi

if docker info >/dev/null 2>&1; then
  say "daemon already answering"
else
  if ! command -v dockerd >/dev/null 2>&1; then
    say "the docker client is installed but dockerd is not, and no daemon is answering."
    say "On Docker Desktop: start the app. On Linux: install docker-ce, or 'sudo systemctl start docker'."
    exit 1
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    say "starting dockerd via systemd"
    sudo -n systemctl start docker 2>/dev/null || systemctl start docker
  else
    say "no init system — starting dockerd directly (log: $LOG_DIR/dockerd.log)"
    # setsid: the daemon outlives this shell and its process group.
    setsid nohup dockerd >"$LOG_DIR/dockerd.log" 2>&1 < /dev/null &
  fi
  for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
  if ! docker info >/dev/null 2>&1; then
    say "dockerd did not come up in 30 s. Last log lines:"
    tail -20 "$LOG_DIR/dockerd.log" 2>/dev/null || true
    exit 1
  fi
  say "daemon up: $(docker info --format '{{.ServerVersion}} storage={{.Driver}} cgroup={{.CgroupVersion}}')"
fi

# --- cloud mode -------------------------------------------------------------------
proxy="${HTTPS_PROXY:-${https_proxy:-}}"
if [[ "$proxy" =~ ^http://(127\.0\.0\.1|localhost):([0-9]+)/?$ ]]; then
  pport="${BASH_REMATCH[2]}"
  ca="${EXTRA_CA_BUNDLE:-${SSL_CERT_FILE:-${NODE_EXTRA_CA_CERTS:-}}}"
  for c in "$ca" /root/.ccr/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
    [[ -n "$c" && -r "$c" ]] && { ca="$c"; break; }
  done
  bridge_ip="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
  rport=$((pport + 1))
  if ! node -e "const s=require('net').connect($rport,'$bridge_ip',()=>process.exit(0));s.on('error',()=>process.exit(1))" 2>/dev/null; then
    setsid nohup node scripts/relay.mjs "$bridge_ip" "$rport" 127.0.0.1 "$pport" >"$LOG_DIR/relay.log" 2>&1 < /dev/null &
    sleep 0.5
  fi
  cat > .env <<EOF
# Written by scripts/docker-up.sh (cloud mode). Safe to delete on an ordinary machine.
COMPOSE_FILE=compose.yaml:compose.cloud.yaml
UPSTREAM_PROXY=http://host.docker.internal:$rport
EXTRA_CA_BUNDLE=$ca
EOF
  say "cloud mode on: relay $bridge_ip:$rport -> 127.0.0.1:$pport, CA $ca (.env written)"
  # Image pulls and builds go through the daemon, which inherits HTTPS_PROXY.
fi
