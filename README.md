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
- Fail closed: no policy, an empty policy, or a receipt that cannot be written means nothing gets out. A malformed policy stops the gate from starting; a malformed edit while running keeps the last good policy and writes a `policy-error` receipt.
- Limits: 2 CPUs, 4 GB memory, 512 processes, 1 GB `/tmp`, 256 concurrent connections through the gate. Edit `compose.yaml` to change them.
- Not yet: grants instead of raw keys, and receipts for actions other than network egress. Those come with the Runtime wiring.

Change the allowlist without a restart: edit `policy/allow.txt`. It takes effect within 2 seconds and leaves a `policy-reload` receipt.

## Known limits
Said plainly, so nobody relies on a wall that isn't there.
- The gate decides by name at connect time and does not look inside TLS. On a shared CDN, an allowed name and a disallowed one can sit on the same servers, and the gate cannot tell them apart once the tunnel is up.
- `receipts/egress.jsonl` grows without bound. Rotate or archive it yourself for now.
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

On a host whose only exit is a local HTTPS proxy (a cloud agent container), `scripts/docker-up.sh` turns on `compose.cloud.yaml`. The gate chains to that proxy and the sandbox trusts its CA. The gate's allowlist still decides first.

## Tests
```bash
npm test
```
Zero dependencies, no Docker. 16 tests covering the policy, the real gate server in process, the private-address refusal, reload and watch, and every fail-closed path.

`.github/workflows/ci.yml` runs those tests and then `vm-up.sh` + `vm-check.sh` on a GitHub runner with open internet, where "no route around the gate" is a real test and not a given. The receipts from that run are attached to the job as an artifact.

## Roadmap + contributing
Strangers need a door in. Good first issues will be labeled `good first issue` — three to start — once the first setup file is published. Do not claim issues exist before they do.

## Releases, Discussions, Social preview image
- Releases: tagged releases only, starting at v0.1, once there is code to release.
- Discussions: on, for questions and roadmap.
- Social preview: 1280x640 card for link shares, to be added — no image is claimed until it is uploaded.
