# Pinned by digest, so a rebuild gets the same bytes and a poisoned tag cannot
# slide in. Dependabot (.github/dependabot.yml) proposes digest bumps weekly.
FROM node:26-alpine@sha256:c6ad9e9c1d80f6eb607c26b4b0a132ff7a2344fad1c78ea3baa2a7d4c8de6d94

# The gate runs `node gate.mjs` and nothing else. npm, npx, corepack and yarn ship
# dozens of bundled dependencies the gate never loads, and a vulnerability scan found
# 10 HIGH-severity CVEs in exactly those. No package manager in the image also means
# nothing in it can install anything.
RUN rm -rf /usr/local/lib/node_modules \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-* \
 && ! command -v npm

WORKDIR /gate
COPY gate.mjs ./
USER node
EXPOSE 3128
CMD ["node", "gate.mjs"]
