ARG RUNTIME_IMAGE=ghcr.io/cheftaco/hive-node-runtime:26.13.1-1@sha256:7671ab0a702c273c37a84d089ba6fe821c6d85cbeab888e7e43522a057da5e6d
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
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
