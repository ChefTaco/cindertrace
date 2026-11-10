ARG RUNTIME_IMAGE=ghcr.io/cheftaco/hive-node-runtime:26.13.0-1@sha256:48948514bce59a27f8ee2a3eabaea0a04cbfa87e087297a52f8501c0d465c84f
FROM node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS build
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /build
COPY package.json package-lock.json ./
COPY apps/security-console/package.json apps/security-console/package.json
COPY services/security-fusion/package.json services/security-fusion/package.json
COPY services/security-collector/package.json services/security-collector/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/integrations/package.json packages/integrations/package.json
RUN npm ci
COPY . .
RUN npm run build && npm run stage -w @cindertrace/console && node scripts/stage-runtime.mjs && node scripts/check-private.mjs --artifact artifacts/runtime
FROM ${RUNTIME_IMAGE} AS runtime
USER root
ENV PATH=/usr/libexec/postgresql18:$PATH
# Maintained PostgreSQL clients use the final distribution's compatible libraries.
RUN apk add --no-cache postgresql-18-client-base && pg_dump --version && pg_restore --version && psql --version
WORKDIR /app
COPY --from=build /build/artifacts/runtime ./
# Preserve the node-only migration compatibility command; npm is absent from the runtime.
COPY --chmod=0755 scripts/npm-compat.sh /usr/local/bin/npm
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
USER node
CMD ["node", "services/security-fusion/dist/index.js"]
