# syntax=docker/dockerfile:1.7
# Multi-stage build:
#   stage 1 (build)   — install dev deps + compile TypeScript
#   stage 2 (runtime) — production deps only, non-root, slim image
#
# Build from the project root:
#   docker build -f deploy/Dockerfile -t nist-express:latest .
# or via compose:
#   docker compose -f deploy/docker-compose.yml up -d --build
#
# The installed tree pins PORT=8080 per CLAUDE.md §2. The release
# tree under releases/<version>/ is rebuilt by scripts/build-release.sh
# with PORT=8080 + EXPOSE 8080 (CLAUDE.md §4).

FROM node:22-alpine AS build
WORKDIR /app
ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
COPY package.json package-lock.json* ./
RUN npm ci --no-audit
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    PORT=8080

# wget for the healthcheck, tini for PID-1 signal handling,
# openssl for the first-boot self-signed cert (deploy/docker-entrypoint.sh).
RUN apk add --no-cache wget tini openssl

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --no-audit && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY public ./public
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Use the built-in non-root `node` user that node:alpine ships with.
RUN mkdir -p /app/.data /app/.run && chown -R node:node /app
USER node

EXPOSE 8080
VOLUME ["/app/.data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD wget --no-check-certificate -qO- "https://127.0.0.1:${PORT}/readyz" || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "dist/server.js"]
