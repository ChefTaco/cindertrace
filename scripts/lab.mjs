import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { readEnvironment } from './upgrade-policy.mjs';
const [operation = 'status', confirmation] = process.argv.slice(2);
if (!['up', 'status', 'stop', 'destroy'].includes(operation)) throw new Error('Usage: npm run lab -- up|status|stop|destroy [exact-project-name]');
const root = resolve('.');
const env = readEnvironment(readFileSync(resolve(root, '.env'), 'utf8'));
const id = env.CINDERTRACE_LAB_INSTALLATION_ID;
const project = `cindertrace-lab-${id}`;
if (env.CINDERTRACE_LAB_ENABLED !== 'true' || !/^[a-f0-9]{24}$/.test(id ?? '') || env.CINDERTRACE_LAB_CONFIRM !== 'isolated-synthetic-installation' || env.COMPOSE_PROJECT_NAME !== project || new URL(env.DATABASE_URL).pathname !== `/cindertrace_lab_${id}`)
  throw new Error('Refusing to manage anything except a newly initialized dedicated lab');
if (operation === 'destroy' && confirmation !== project) throw new Error('Destroy requires the exact COMPOSE_PROJECT_NAME from this lab configuration');
const args = operation === 'up' ? ['up', '--build', '-d', '--wait'] : operation === 'status' ? ['ps'] : operation === 'stop' ? ['stop'] : ['down', '--volumes', '--remove-orphans'];
const result = spawnSync('docker', ['compose', '--project-directory', root, '--env-file', resolve(root, '.env'), '-p', project, ...args], {cwd: root, stdio: 'inherit'});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
