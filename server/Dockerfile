# CipherChat server — single-process Node + embedded SQLite.
# Mount a persistent volume and set CIPHERCHAT_DATA_DIR to its path
# (e.g. /data) so the database survives redeploys.
FROM node:22-slim

WORKDIR /app
ENV NODE_ENV=production

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public

ENV PORT=4000
ENV CIPHERCHAT_DATA_DIR=/data
EXPOSE 4000

CMD ["node", "src/index.js"]
