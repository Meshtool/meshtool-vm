# The box the agent works in. node:22-bookworm already carries git, curl,
# python3 and a compiler toolchain, so building this image needs no network
# beyond the base-image pull — it builds the same behind a strict proxy.
FROM node:22-bookworm
# Uid 1000 ("node") is the only user the agent gets. No sudo is installed.
USER node
WORKDIR /work
ENV HOME=/home/node \
    NPM_CONFIG_CACHE=/tmp/.npm \
    NPM_CONFIG_UPDATE_NOTIFIER=false
CMD ["sleep", "infinity"]
