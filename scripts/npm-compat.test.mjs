import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const script = resolve(root, 'scripts/npm-compat.sh');

test('runtime npm compatibility script rejects every command except the Compose migration', () => {
  for (const args of [[], ['install'], ['run'], ['run', 'db:migrate', '--', 'x'], ['exec', 'node'], ['run', 'build']]) {
    const result = spawnSync('sh', [script, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 127, args.join(' '));
    assert.match(result.stderr, /npm is not installed/);
  }
  const compose = readFileSync(resolve(root, 'compose.yaml'), 'utf8');
  assert.match(compose, /command: \[npm, run, db:migrate\]/);
  assert.match(readFileSync(script, 'utf8'), /cd \/app\/services\/security-fusion\n  exec node scripts\/apply-migrations\.mjs\n/);
});

test('runtime uses the pinned maintained base and keeps only the migration compatibility command', () => {
  const dockerfile = readFileSync(resolve(root, 'Dockerfile'), 'utf8');
  assert.match(dockerfile, /ARG RUNTIME_IMAGE=ghcr\.io\/cheftaco\/hive-node-runtime:26\.[0-9.]+-[0-9]+@sha256:[a-f0-9]{64}/);
  const runtime = dockerfile.slice(dockerfile.lastIndexOf('\nFROM '));
  assert.match(runtime, /FROM \$\{RUNTIME_IMAGE\} AS runtime/);
  assert.doesNotMatch(runtime, /apt-get|dpkg|COPY --from=.*\/(usr|lib|bin)/);
  assert.match(runtime, /apk add --no-cache postgresql-18-client-base/);
  assert.match(runtime, /COPY --chmod=0755 scripts\/npm-compat.sh \/usr\/local\/bin\/npm/);
});
