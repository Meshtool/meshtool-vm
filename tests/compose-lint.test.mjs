// A static guard on the files that define the walls. If someone later adds an
// env_file, mounts the Docker socket, publishes a port, or hands the sandbox a
// second network, this goes red before any container does. Zero-dep: the compose
// files are plain enough that line-level checks are exact.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');
// Drop comments, and any line that is nothing but a comment or blank.
const strip = (t) => t.split('\n').map((l) => l.replace(/(^|\s)#.*$/, '').trimEnd()).filter((l) => l !== '').join('\n') + '\n';

const FILES = { 'compose.yaml': strip(read('compose.yaml')), 'compose.cloud.yaml': strip(read('compose.cloud.yaml')) };

// The service blocks of one compose file: name -> its text.
function services(text) {
  const out = {};
  let cur = null, inServices = false;
  for (const line of text.split('\n')) {
    if (/^\S/.test(line)) { inServices = /^services:/.test(line); cur = null; continue; }
    if (!inServices) continue;
    const m = line.match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
    if (m) { cur = m[1]; out[cur] = ''; continue; }
    if (cur) out[cur] += line + '\n';
  }
  return out;
}
const topBlock = (text, name) => {
  const m = text.match(new RegExp(`^${name}:\\s*\\n((?: .*\\n?|\\n)*)`, 'm'));
  return m ? m[1] : '';
};

const NEVER = [
  [/env_file/, 'env_file: secrets must never be handed to the sandbox wholesale'],
  [/docker\.sock/, 'the Docker socket is root on the host'],
  [/privileged/, 'privileged defeats every other wall'],
  [/network_mode/, 'network_mode skips the gate\'s network'],
  [/cap_add/, 'capabilities stay dropped'],
  [/^\s*pid:/m, 'a shared PID namespace shows the host\'s processes'],
  [/^\s*ipc:/m, 'a shared IPC namespace shares host memory'],
  [/userns_mode/, 'userns_mode: host removes user-namespace remapping'],
  [/^\s*devices:/m, 'no host devices'],
  [/^\s*ports:/m, 'nothing is published to the host'],
  [/^\s*sysctls:/m, 'no kernel knobs'],
];

for (const [file, text] of Object.entries(FILES)) {
  for (const [re, why] of NEVER) {
    test(`${file}: never ${re.source.replace(/\\/g, '')} — ${why}`, () => assert.doesNotMatch(text, re));
  }

  test(`${file}: no volume mounts the host root, a home directory, or credentials`, () => {
    // Only real `volumes:` lists — a tmpfs entry like /home/node is memory, not the host.
    const vols = [];
    let inVolumes = false;
    for (const l of text.split('\n')) {
      if (/^\s+volumes:\s*$/.test(l)) { inVolumes = true; continue; }
      if (inVolumes && /^\s+- /.test(l)) { vols.push(l); continue; }
      inVolumes = false;
    }
    assert.ok(vols.length > 0, 'found the volume lists (a lint that finds nothing proves nothing)');
    for (const v of vols) {
      assert.doesNotMatch(v, /- *["']?\/:/, `host root: ${v}`);
      assert.doesNotMatch(v, /~|\$\{?HOME\}?|\/root|\/home\//, `home directory: ${v}`);
      assert.doesNotMatch(v, /\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.npmrc|\.netrc|\.git-credentials|\.config/, `credentials: ${v}`);
    }
  });

  test(`${file}: no environment variable named like a secret`, () => {
    for (const m of text.matchAll(/^\s+([A-Z][A-Z0-9_]*):/gm)) {
      assert.doesNotMatch(m[1], /KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL/, `environment variable ${m[1]}`);
    }
  });
}

test('compose.yaml: both services take the hardened baseline, and the baseline holds', () => {
  const t = FILES['compose.yaml'];
  const svc = services(t);
  assert.deepEqual(Object.keys(svc).sort(), ['gate', 'sandbox']);
  for (const [name, body] of Object.entries(svc)) assert.match(body, /<<: \*hardened/, `${name} takes *hardened`);
  const base = t.match(/x-hardened:\s*&hardened\n((?: {2}.*\n)+)/)?.[1] ?? '';
  assert.match(base, /read_only: true/);
  assert.match(base, /cap_drop: \[ALL\]/);
  assert.match(base, /no-new-privileges:true/);
  assert.match(base, /init: true/);
});

test('compose.yaml: the sandbox is on the inside network only, as a non-root user, with limits', () => {
  const sb = services(FILES['compose.yaml']).sandbox;
  assert.match(sb, /networks: \[inside\]\s*$/m, 'networks must be exactly [inside]');
  assert.doesNotMatch(sb, /outside/);
  assert.doesNotMatch(sb, /^\s*user:/m, 'the image sets the user; do not override it');
  assert.match(sb, /pids_limit: \d+/);
  assert.match(sb, /mem_limit: \S+/);
  assert.match(sb, /cpus: \S+/);
  assert.match(sb, /HTTPS_PROXY: http:\/\/gate:3128/);
});

test('compose.yaml: the gate is the only service on both networks', () => {
  const svc = services(FILES['compose.yaml']);
  assert.match(svc.gate, /networks: \[inside, outside\]/);
  assert.match(svc.gate, /GATE_UPLOAD_BUDGET_MB: \$\{GATE_UPLOAD_BUDGET_MB:-[1-9]\d*\}/, 'the default upload budget must not be 0');
  assert.match(svc.gate, /\.\/policy:\/policy:ro/, 'the gate reads its policy read-only');
});

test('compose.yaml: the inside network is internal, isolated, and has no IPv6', () => {
  const inside = topBlock(FILES['compose.yaml'], 'networks').match(/ {2}inside:\n((?: {4}.*\n)+)/)?.[1] ?? '';
  assert.match(inside, /internal: true/);
  assert.match(inside, /enable_ipv6: false/);
  assert.match(inside, /gateway_mode_ipv4: isolated/);
  assert.match(inside, /gateway_mode_ipv6: isolated/);
});

test('compose.cloud.yaml: the relay is a read-only socket mount into the gate only', () => {
  const svc = services(FILES['compose.cloud.yaml']);
  assert.match(svc.gate, /- \.\/run:\/run\/relay:ro/);
  assert.doesNotMatch(svc.sandbox, /\/run\/relay/, 'the sandbox must never see the relay');
  assert.doesNotMatch(FILES['compose.cloud.yaml'], /extra_hosts|host-gateway|host\.docker\.internal/, 'no path to the host over the network');
});

test('both Dockerfiles pin their base image by digest, so a rebuild gets the same bytes', () => {
  for (const f of ['gate/Dockerfile', 'sandbox/Dockerfile']) {
    const froms = [...read(f).matchAll(/^FROM\s+(\S+)/gm)].map((m) => m[1]);
    assert.ok(froms.length, `${f} has a FROM`);
    for (const from of froms) assert.match(from, /@sha256:[0-9a-f]{64}$/, `${f}: ${from} is not pinned by digest`);
  }
});

test('the gate image carries no package manager (it only ever runs `node gate.mjs`)', () => {
  const df = read('gate/Dockerfile');
  assert.match(df, /rm -rf \/usr\/local\/lib\/node_modules/);
  assert.match(df, /!\s*command -v npm/, 'the build must assert npm is really gone');
});

test('CI scans both images with a digest-pinned scanner, and Dependabot keeps the pins fresh', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /aquasec\/trivy@sha256:[0-9a-f]{64}/, 'the scanner itself is pinned');
  assert.match(ci, /meshtool-vm-gate:latest/);
  assert.match(ci, /meshtool-vm-sandbox:latest/);
  const dep = read('.github/dependabot.yml');
  for (const dir of ['/gate', '/sandbox']) assert.match(dep, new RegExp(`package-ecosystem: docker[\\s\\S]*?directory: ${dir}`), `Dependabot watches ${dir}`);
});

test('both Dockerfiles end as a non-root user', () => {
  for (const f of ['gate/Dockerfile', 'sandbox/Dockerfile']) {
    const users = [...read(f).matchAll(/^USER\s+(\S+)/gm)].map((m) => m[1]);
    assert.ok(users.length, `${f} sets a USER`);
    assert.doesNotMatch(users.at(-1), /^(root|0)$/, `${f} ends as ${users.at(-1)}`);
  }
});
