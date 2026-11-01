FROM node:22-alpine
WORKDIR /gate
COPY gate.mjs ./
USER node
EXPOSE 3128
CMD ["node", "gate.mjs"]
