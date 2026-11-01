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
Build status, license, release, and Discord badges to be added once the first workflow and release exist. No badge is shown until it is real.

## Quickstart: one command
Needs Docker (Docker Desktop on Windows/macOS, Docker Engine on Linux) and Node 18+ on the host.

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
- It can't: run as root, hold any Linux capability, write system files, escalate through setuid, reach a host not on the allowlist, connect to a raw IP, or get around the gate. The sandbox's network has no route out except the gate, so a tool that ignores the proxy settings simply has nowhere to go.
- Fail closed: no policy, an empty policy, or a receipt that cannot be written means nothing gets out. A malformed policy line stops the gate from starting.
- Limits: 2 CPUs, 4 GB memory, 512 processes, 1 GB `/tmp`. Edit `compose.yaml` to change them.
- Not yet: grants instead of raw keys, and receipts for actions other than network egress. Those come with the Runtime wiring.

Change the allowlist without a restart: edit `policy/allow.txt`, then `docker compose kill -s HUP gate`.

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
node --test tests/gate.test.mjs
```
Zero dependencies, no Docker. Covers the policy, the real gate server, and both fail-closed paths.

## Roadmap + contributing
Strangers need a door in. Good first issues will be labeled `good first issue` — three to start — once the first setup file is published. Do not claim issues exist before they do.

## Releases, Discussions, Social preview image
- Releases: tagged releases only, starting at v0.1, once there is code to release.
- Discussions: on, for questions and roadmap.
- Social preview: 1280x640 card for link shares, to be added — no image is claimed until it is uploaded.
