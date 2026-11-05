#!/bin/sh
# The runtime image does not include npm. Compose files from earlier releases run
# the migrate service as `npm run db:migrate`, and managed upgrades require that
# command to stay unchanged, so this one invocation is kept. Anything else fails.
set -eu
if [ "$#" -eq 2 ] && [ "$1" = run ] && [ "$2" = db:migrate ]; then
  cd /app/services/security-fusion
  exec node scripts/apply-migrations.mjs
fi
echo "npm is not installed in the Cindertrace runtime image. Run migrations with: node scripts/apply-migrations.mjs (in /app/services/security-fusion)." >&2
exit 127
