# Meshtool VM

Local VM where an agent finishes your loose ends, inside a sandbox you control.

## Start with the real pieces, already public and live
- Runtime — the gatekeeper for your agents: https://runtime.meshtool.ai
- Market — the live front door: https://market.meshtool.ai
- Meshtool SDK — TypeScript SDK and CLI for the MeshTool API: https://github.com/Meshtool/meshtool-sdk
- MeshMarket MCP — connect any MCP client to the Meshtool platform and MeshMarket exchange: https://github.com/Meshtool/meshmarket-mcp
- Examples — copy-paste starters: https://github.com/Meshtool/examples

## One-line promise + demo clip
Agents don't log in anymore. They clock in — and finish the loose ends inside a VM you control.
Demo clip: to be added — 60 seconds, no sound needed.

## Badges
[![ci](https://github.com/Meshtool/meshtool-vm/actions/workflows/ci.yml/badge.svg)](https://github.com/Meshtool/meshtool-vm/actions/workflows/ci.yml)

License, release and Discord badges are added when each exists. No badge is shown until it is real.

## Quickstart: one command
Needs Docker Engine 28 or newer (Docker Desktop on Windows/macOS, Docker Engine on Linux) and Node 18+ on the host.

```bash
./scripts/vm-up.sh
```

That starts the Docker daemon if it isn't answering, builds the two containers, and waits until both are healthy. Then:

```bash
docker compose exec sandbox bash
```

```bash
./scripts/vm-check.sh
```

`vm-check.sh` proves the walls from inside the sandbox and exits non-zero if any fails. Receipts land in `receipts/egress.jsonl`.

## What it can and can't do
Sandbox v0.1: one box, one way out, and a receipt for every attempt.
- It can: work in `/work` (your folder, mounted), use git, Node, Python and a compiler, and reach the hosts in `policy/allow.txt` (npm, PyPI, GitHub, the Meshtool platform by default).
- It can't: run as root, hold any Linux capability, write system files, escalate through setuid, reach a host not on the allowlist, connect to a raw IP, or get around the gate. The sandbox's network has no route out and the host has no address on it, so a tool that ignores the proxy settings has nowhere to go — not even to a service listening on your machine. Outside names do not resolve from inside, so DNS cannot carry data out either.
- An allowlisted name that resolves to a loopback, LAN or link-local address is refused. The policy names public services, never the host or the LAN.
- **Upload budget.** An allowed name is still a way out, so the gate caps what one host may be sent: 100 MB per host per hour by default (`GATE_UPLOAD_BUDGET_MB`, `0` turns it off). Past the cap the tunnel is cut, a `budget-exceeded` receipt is written, and new connections to that host are refused until the hour rolls over. Downloads are not counted. This makes bulk exfiltration through an allowed host loud and slow; it does not make it impossible.
- **Tamper-evident receipts.** Every receipt carries the hash of the one before it, and the first receipt of each run records the hash of the policy in force. An edit, deletion or reorder anywhere in the middle of `receipts/egress.jsonl` breaks the chain. Check it any time with `npm run verify`; `vm-check` also compares it against the running gate's live head, which is what catches a cut tail.
- **Shell receipts.** `./scripts/vm-shell.sh` opens a shell in the sandbox (or runs one command: `./scripts/vm-shell.sh -- npm test`) and records who, from which machine, when it started and ended, and the true exit code, in `receipts/shell.jsonl`, its own hash chain. For a command it keeps the program name and a hash of the argument list, not the text (command lines can hold secrets). It refuses to open a shell it cannot record.
- **Supply chain.** Both base images are pinned by digest, so a rebuild gets the same bytes, and Dependabot proposes bumps weekly so a pin never means a CVE that never gets fixed. The gate image has no npm, npx, corepack or yarn (it only runs `node gate.mjs`; a scan found 10 HIGH CVEs in exactly those bundled packages), and the sandbox has ImageMagick removed (13 more). CI scans both images with a digest-pinned Trivy: the gate must have zero HIGH/CRITICAL findings that have a fix, and so must the sandbox's OS packages.
- **No secrets in the box.** `vm-check` fails if any variable in the sandbox is named like a secret or shaped like a token or private key, and a lint test (`tests/compose-lint.test.mjs`) fails the build if anyone adds an `env_file`, mounts the Docker socket or a home directory, publishes a port, adds a capability, or puts the sandbox on a second network.
- Fail closed: no policy, an empty policy, or a receipt that cannot be written means nothing gets out. A malformed policy stops the gate from starting; a malformed edit while running keeps the last good policy and writes a `policy-error` receipt. A gate that cannot write receipts reports itself unhealthy (`/healthz` is 503) and says why in its log, so it never looks fine while quietly refusing everything.
- Limits: 2 CPUs, 4 GB memory, 512 processes, 1 GB `/tmp`, 256 concurrent connections through the gate. Edit `compose.yaml` to change them.
- Not yet: grants instead of raw keys, and receipts for actions other than network egress. Those come with the Runtime wiring.

Change the allowlist without a restart: edit `policy/allow.txt`. It takes effect within 2 seconds and leaves a `policy-reload` receipt.

## Known limits
Said plainly, so nobody relies on a wall that isn't there.
- The gate decides by name at connect time and does not look inside TLS. On a shared CDN, an allowed name and a disallowed one can sit on the same servers, and the gate cannot tell them apart once the tunnel is up.
- `receipts/egress.jsonl` grows without bound. Rotate or archive it yourself for now.
- `vm-shell.sh` is an audit aid, not a wall: anyone with Docker access can `docker exec` straight into the container and leave no trace in `shell.jsonl`. It tells you who came in through the front door.
- The hash chain proves the middle of the file is untouched. It cannot see a cut tail, or a whole file replaced by a freshly forged one, unless it can compare against the running gate's head (which `vm-check` does). Once the gate restarts it adopts whatever file it finds, so a truncation made while it was down is invisible afterwards. For anything that matters, keep a copy of the head hash (or the file) somewhere the sandbox host cannot reach.
- The sandbox still carries npm's own bundled dependencies (10 HIGH CVEs with fixes, all in the npm 10 line that Node 22 ships). The agent legitimately uses npm, so it cannot be removed; fixing it means pinning npm 11, which needs network at image-build time and so needs a design for strict hosts. CI shows the finding on every run but does not yet fail on it.
- Removing ImageMagick also removed some image-library `-dev` packages (cairo, rsvg, gdk-pixbuf). Native npm modules that compile against them will not build in the sandbox.
- The upload budget counts bytes sent, TLS overhead included. A patient agent that stays under it, hour after hour, still gets data out through an allowed name.
- The IPv6 check passes vacuously on a kernel without IPv6 (as in some cloud containers); CI runs it on a runner that has it.
- `work/` is your folder, mounted read-write. Whatever the agent writes there is on your machine. Treat it like output from a stranger.
- Receipts cover the network only. What the agent runs inside the box is not recorded yet.

## Architecture diagram
```text
 your folder ──mount──> ┌──────────── sandbox ────────────┐
                        │ uid 1000, read-only, no caps     │
                        └──────────────┬───────────────────┘
                     network "inside" (internal: no route out)
                                       │
                        ┌──────────── gate ───────────────┐   receipts/egress.jsonl
                        │ allowlist, fail closed, receipts │──> one line per attempt
                        └──────────────┬───────────────────┘
                              network "outside"
                                       │
                               allowlisted hosts
```

On a host whose only exit is a local HTTPS proxy (a cloud agent container), `scripts/docker-up.sh` turns on `compose.cloud.yaml`. A small relay (`scripts/relay.mjs`) serves that proxy on a **unix socket** in `./run`, owned by uid 1000 with mode 0600, and only the gate container mounts it. It is not a network port, so nothing else on any Docker network can reach it, and the sandbox cannot see it. The sandbox trusts the proxy's CA, and the gate's allowlist still decides first.

## Tests
```bash
npm test
```
Zero dependencies, no Docker; needs Node 22 (`--test-force-exit`, so a failing test fails the run instead of hanging it). 83 tests: the policy, the real gate server in process, the private-address refusal, reload and watch, the hash chain (every tamper case, plus restart continuity), the upload budget, the shell log (ten concurrent writers, lock and stale-lock handling), the unix-socket upstream, address selection (IPv4 first, fallback, any-private refusal, resolver failure), `/healthz`, and the compose and Dockerfile lint. Each wall's check was proven by removing the wall and watching the check go red.

`.github/workflows/ci.yml` runs those tests and then `vm-up.sh` + `vm-check.sh` on a GitHub runner with open internet, where "no route around the gate" is a real test and not a given. The receipts from that run are attached to the job as an artifact.

## Roadmap + contributing
Strangers need a door in. Good first issues will be labeled `good first issue` — three to start — once the first setup file is published. Do not claim issues exist before they do.

## Releases, Discussions, Social preview image
- Releases: tagged releases only, starting at v0.1, once there is code to release.
- Discussions: on, for questions and roadmap.
- Social preview: 1280x640 card for link shares, to be added — no image is claimed until it is uploaded.
