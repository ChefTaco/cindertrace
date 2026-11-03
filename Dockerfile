FROM postgres:18.6-bookworm@sha256:5c4783a8cc3f0074912164f94dfa1be4e043438f0f707cf968d7af9a0d31a2c8 AS postgres-tools
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
RUN npm run build && npm run stage -w @cindertrace/console && node scripts/stage-runtime.mjs
FROM node:24.22.1-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates postgresql-client openssl && rm -rf /var/lib/apt/lists/*
COPY --from=postgres-tools /usr/lib/postgresql/18/bin/pg_dump /usr/local/bin/pg_dump
COPY --from=postgres-tools /usr/lib/postgresql/18/bin/pg_restore /usr/local/bin/pg_restore
COPY --from=postgres-tools /usr/lib/postgresql/18/bin/psql /usr/local/bin/psql
COPY --from=postgres-tools /usr/lib/x86_64-linux-gnu/libpq.so.5.18 /usr/lib/x86_64-linux-gnu/libpq.so.5
WORKDIR /app
COPY --from=build /build/artifacts/runtime ./
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
USER node
CMD ["node", "services/security-fusion/dist/index.js"]
