ARG RUNTIME_IMAGE=ghcr.io/cheftaco/hive-node-runtime:26.13.1-1@sha256:7671ab0a702c273c37a84d089ba6fe821c6d85cbeab888e7e43522a057da5e6d
# Build on the runtime image's Node major, so native modules and the bundle match what runs.
FROM node:26.13.1-bookworm-slim@sha256:0042e17d232a87a2cd485be1da7900fca4d10a4ad11b29e9285da1d2e54798c9 AS build
WORKDIR /build
COPY package.json package-lock.json ./
COPY services/security-fusion/package.json services/security-fusion/package.json
COPY services/security-collector/package.json services/security-collector/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/integrations/package.json packages/integrations/package.json
RUN npm ci
COPY . .
RUN npm run build && node scripts/stage-runtime.mjs && node scripts/check-private.mjs --artifact artifacts/runtime
FROM ${RUNTIME_IMAGE} AS runtime
USER root
ENV PATH=/usr/libexec/postgresql18:$PATH
# Maintained PostgreSQL clients use the final distribution's compatible libraries.
# libzstd1 1.6.0 fixes CVE-2026-124851 (zstd 1.5.1 to 1.5.7); the build fails on an older one.
RUN apk add --no-cache 'libzstd1>=1.6.0' postgresql-18-client-base \
  && zstd_version="$(apk info -e -v libzstd1)" && zstd_version="${zstd_version#libzstd1-}" \
  && test "$(apk version -t "$zstd_version" 1.6.0)" != '<' \
  && pg_dump --version && pg_restore --version && psql --version
WORKDIR /app
COPY --from=build /build/artifacts/runtime ./
# Preserve the node-only migration compatibility command; npm is absent from the runtime.
COPY --chmod=0755 scripts/npm-compat.sh /usr/local/bin/npm
ENV NODE_ENV=production
USER node
CMD ["node", "services/security-fusion/dist/index.js"]
