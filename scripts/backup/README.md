# Meshtool seat and workspace recovery

Extends the existing `/home/meshtool/own-rails-backup/backup.sh` cron job (09:30 UTC).
The original script is preserved as `backup.sh.pre-seat-20261108`. No live service
is stopped, paused, restarted, reconfigured, or mounted into a restore container.

## Coverage

- Existing consistent staging PostgreSQL dump (production-derived sensitive data).
- Rivet's entire persistent `/data` volume: saved memory, sessions, projects,
  storage checkpoint and Chromium profile.
- `/home/meshtool/{projects,frank-deck-work,seat-spike,shared,own-rails-staging,own-rails-backup}`,
  including `.git`, uncommitted files, operational configuration and private seat files.
- The current OpenShell seat's `/sandbox` and `/home/ubuntu`, even though these
  live in the container writable layer. Exactly one seat must match; inventory
  changes fail closed instead of silently omitting a new seat.

Excluded: node_modules, explicitly named browser caches, Python bytecode caches,
Chromium singleton runtime handles, sockets, and SQLite sidecars superseded by a
verified standalone database. The encrypted manifest lists exclusions and every
file hash. Existing external symlinks are preserved, not dereferenced: their
external targets are not claimed as backed up. Other VM services, the operating
system, Docker images, host shared brain and arbitrary home-directory files are
outside this addition. Brain backup remains the existing estate-backup workflow.

## Consistency and security

SQLite uses online backup. If Chromium holds a lifetime lock, a private copy of
the DB and journals is accepted only after matching before/after hashes, recovered
away from the source and integrity-checked. Other files must stay byte-stable
through capture; tree changes fail the run. This is not a globally atomic snapshot
across applications. The saved browser storage checkpoint remains the same recovery
fallback used by the seat itself. Nothing is written to source stores.

Backup folders are mode 700, archives 600. Plaintext staging archives and dumps
are removed only after the independent encrypted download and restore succeeds;
full encrypted copies remain on the host and R2. Failed offsite runs retain their
private staging data for retry. Historical backups are not changed. No plaintext archive is written to the
Windows host or sent to R2. The host uses existing guarded vault access and the
existing ESTBAK01 AES-256-GCM/scrypt implementation and escrowed
`ESTATE_BACKUP_PASSPHRASE`. Escrow location is recorded in HQ `backup-escrow.json`;
this work does not independently re-attest DW's recovery-key custody.

R2 uses the existing private `estate-backup` bucket under `meshtool-vm/`.
Wrangler's 300 MiB limit requires 100 MiB ciphertext parts. A descriptor records
part order, sizes and hashes. Download all descriptor parts in order, concatenate,
check the whole ciphertext hash, then use HQ `decrypt` with the escrowed passphrase.
Authentication must succeed before any extraction. The descriptor carries no
plaintext workspace data or secrets.

## Restore proof

`offsite.mjs` downloads the exact R2 parts and descriptor, verifies hashes and
GCM authentication, rejects wrong passwords and changed ciphertext, then streams
decrypted bytes via SSH stdin to `restore.py`. The restore is into a fresh private
directory, never a live volume. It verifies every file, numeric owner/group and permissions, SQLite integrity, JSON
state, restores the OpenShell tar, opens Chromium as Rivet's normal UID 1000 on a copied profile and restores
saved cookies in a `--network none` container. It also restores the actual SQL
dump into an isolated PostgreSQL container with no published ports. A deliberately
modified restored memory file must fail the same verifier. Test containers contain
no live mounts; the browser mounts only the restored copy read-only.

`finalize.py` keeps the successful receipt and removes only disposable test restore
files, after the remote download/restore proof. It never deletes live data or R2 objects. The existing seven-day local retention
is applied only to new backups carrying a successful offsite restore receipt;
their independent R2 copies remain. Historical unverified backups are untouched.
Capture refuses when VM free space is below 4 GiB. Monitor space because failed
offsite transfers deliberately retain local data. Failures never advance LATEST or a verified
receipt. Reruns use the same encrypted artifact and object hashes.

The Windows task now uses S4U/Limited under the same account, with no stored
Windows password. It runs daily at 03:00 Pacific and five minutes after startup,
with StartWhenAvailable. The wrapper requires session 0, a batch logon and no
interactive token; an interactive negative control must fail. The S4U candidate
performed a fresh upload/download and full isolated restore before promotion.
It uses file-based SSH authentication (IdentityAgent=none) and an explicit vault
path; network authentication by those existing credentials passed under S4U.
This is not a promise that Windows integrated credentials or EFS work in S4U.
See [Microsoft task logon types](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type).

NETWORK FOLLOW-UP PENDING: Windows Tailscale's unattended flag is currently off.
The user required no live-service changes, so enabling that single flag is awaiting
explicit clarification. The scheduled process itself is login-independent; end-to-end
logout readiness also needs the VM network path to survive logout. Do not treat
service StartType=Automatic as proof of that. See the current owning OPEN-LOOPS.
A successful VM capture alone is not an off-machine backup: require a fresh
latest-verified.json. A physical Windows logout/reboot was not performed because
it would disrupt the user's other work.

## Deployment and checks

Canonical source: `Meshtool/meshtool-vm`, branch `codex/seat-backup-20261108`.
Installed VM scripts: `/home/meshtool/own-rails-backup/`.
Installed host runner and receipts: `C:/backups/meshtool-recovery/` (private ACL).

Run `python3 scripts/backup/test_backup.py` for extraction safety controls and a
real SQLite WAL backup test. Run `bash ~/own-rails-backup/backup.sh` to capture.
Run the host `offsite.mjs` with Windows Node to upload/download/restore the latest
complete capture. Neither command changes live services.

For an interrupted restore after all R2 parts were downloaded, `--reuse-downloads`
rechecks those existing ciphertext files, descriptor and GCM tag without another
network transfer. It fails if any part is absent or changed. `--force-verify`
repeats proof for an already-verified snapshot. Normal scheduled runs always
upload/download each new snapshot. Encrypted host artifacts permit retries after
plaintext staging cleanup. Source-code recovery also has an independently encrypted
Git bundle stored alongside the data backups in R2.
