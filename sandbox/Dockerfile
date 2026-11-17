# The box the agent works in. node:22-bookworm already carries git, curl, python3 and
# a compiler toolchain, so building this image needs no network beyond the base-image
# pull. Pinned by digest; Dependabot (.github/dependabot.yml) proposes bumps weekly.
FROM node:25-bookworm@sha256:78839ac448c23517f8eab2e8f7943d9b4f73979eb7f8bed2c73dbf72ff869e7b

# ImageMagick ships in the full image for building native modules that rarely need it.
# A scan found 13 HIGH CVEs in it, and an agent has no business decoding hostile images
# in a box whose point is containment. Removing packages is offline work (dpkg only).
USER root
RUN apt-get purge -y --auto-remove 'imagemagick*' 'libmagick*' \
 && rm -rf /var/lib/apt/lists/* \
 && git --version && curl --version | head -1 && python3 --version && gcc --version | head -1 && make --version | head -1

# Uid 1000 ("node") is the only user the agent gets. No sudo is installed.
USER node
WORKDIR /work
ENV HOME=/home/node \
    NPM_CONFIG_CACHE=/tmp/.npm \
    NPM_CONFIG_UPDATE_NOTIFIER=false
CMD ["sleep", "infinity"]
