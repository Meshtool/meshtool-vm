# Pinned by digest, so a rebuild gets the same bytes and a poisoned tag cannot
# slide in. Dependabot (.github/dependabot.yml) proposes digest bumps weekly.
FROM node:25-alpine@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4

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
