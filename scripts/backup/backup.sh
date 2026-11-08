#!/usr/bin/env bash
# Staging contains production-derived data. All outputs private; never commit them.
set -euo pipefail
umask 077
DEST="$HOME/own-rails-backups"
mkdir -p "$DEST"; chmod 700 "$DEST"
exec 9>"$DEST/.backup.lock"
flock -n 9 || exit 1
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="$DEST/$stamp"; mkdir -m 700 "$out"
set -a
. "$HOME/own-rails-staging/env/staging.env"
set +a
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" own-rails-pg-staging pg_dump -U runtime -d runtime_staging | gzip > "$out/runtime_staging.sql.gz"
unset POSTGRES_PASSWORD RUNTIME_ADMIN_KEY VAULT_KEY PGPASSWORD
sudo -n python3 "$HOME/own-rails-backup/capture.py" "$out/seat-workspace.tar.gz" > "$out/capture-receipt.json"
sudo -n chown "$(id -u):$(id -g)" "$out/seat-workspace.tar.gz"
docker ps --format '{{.Names}} {{.Status}}' > "$out/containers.txt"
curl --fail --max-time 10 -s http://100.114.162.107:18080/health > "$out/staging-health.json"
df -h / > "$out/disk.txt"
(cd "$out" && sha256sum runtime_staging.sql.gz seat-workspace.tar.gz capture-receipt.json containers.txt staging-health.json disk.txt > SHA256SUMS && sha256sum -c SHA256SUMS >/dev/null)
# COMPLETE is only written after all required targets pass. No automatic purges.
touch "$out/COMPLETE"
printf '%s\n' "$stamp" > "$DEST/LATEST.tmp"
mv "$DEST/LATEST.tmp" "$DEST/LATEST"
echo "backup complete: $stamp" >> "$DEST/backup.log"
echo "backup complete: $stamp"
