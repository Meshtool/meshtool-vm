# Meshtool VM

Local VM where an agent finishes your loose ends, inside a sandbox you control.

## One-line promise + demo clip
Agents don't log in anymore. They clock in — and finish the loose ends inside a VM you control.
Demo clip: to be added — 60 seconds, no sound needed.

## Badges
Build status, license, release, and Discord badges to be added once the first workflow and release exist. No badge is shown until it is real.

## Quickstart: one command
Starter layout for now. The compose / VM setup file is not published in this repo yet, so do not run a quickstart from this README until that file lands.

```text
docker compose up
```

## What it can and can't do
Your differentiator: permissions, limits, what the sandbox blocked, audit trail.
- It can: run agent work inside a sandbox you control, with grants instead of raw keys, and a receipt for what it did.
- It can't: run outside its grants, use a key it was not given, or hide what it did — the audit trail is the point.
- Limits and blocked actions are listed here as the sandbox rules land, not before.

## Architecture diagram
One picture: agent, sandbox, gate, receipts.
Diagram to be added with the first real setup file.

## Roadmap + contributing
Strangers need a door in. Good first issues will be labeled `good first issue` — three to start — once the first setup file is published. Do not claim issues exist before they do.

## Releases, Discussions, Social preview image
- Releases: tagged releases only, starting at v0.1, once there is code to release.
- Discussions: on, for questions and roadmap.
- Social preview: 1280x640 card for link shares, to be added — no image is claimed until it is uploaded.
