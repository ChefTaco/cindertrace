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

test('runtime image removes package managers and apt and installs only the compatibility script', () => {
  const dockerfile = readFileSync(resolve(root, 'Dockerfile'), 'utf8');
  const runtime = dockerfile.slice(dockerfile.lastIndexOf('\nFROM '));
  const removal = runtime.indexOf('rm -rf /usr/local/lib/node_modules/npm');
  assert(removal > 0);
  assert(runtime.indexOf('apt-get') < removal, 'apt is used only before it is purged');
  assert.match(runtime, /dpkg --purge --force-remove-protected --force-remove-essential apt libapt-pkg6\.0/);
  assert(runtime.indexOf('COPY --chmod=0755 scripts/npm-compat.sh /usr/local/bin/npm') > removal);
  assert(runtime.lastIndexOf('apt-get') < removal);
});
