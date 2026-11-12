import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Runtime packages retain executable files, assets and all license/notice files. */
export function runtimeDependencyFile(path) {
  const name = path.split('/').at(-1);
  if (/licen[cs]e|notice|copying|copyright/i.test(name)) return true;
  if (/\.d\.(?:ts|mts|cts)(?:\.map)?$|\.(?:md|markdown|map|tsbuildinfo)$/i.test(name)) return false;
  return true;
}

// createLocalJWKSet and errors are used by the shared Oathweave verifier (@hivemagnus/hive-common).
export const JOSE_RUNTIME_EXPORTS = Object.freeze(['SignJWT', 'jwtVerify', 'createLocalJWKSet', 'createRemoteJWKSet', 'customFetch', 'decodeProtectedHeader', 'errors']);

/** Bundle the production entrypoints; unused key import/export APIs are not shipped. */
export async function bundleJoseRuntime({ root, source, destination }) {
  const { build } = await import('esbuild');
  const result = await build({
    absWorkingDir: root,
    stdin: {
      contents: `export { ${JOSE_RUNTIME_EXPORTS.join(', ')} } from './dist/webapi/index.js';`,
      resolveDir: source,
      sourcefile: 'cindertrace-jose-runtime.mjs',
    },
    bundle: true, platform: 'node', format: 'esm', target: 'node24',
    treeShaking: true, legalComments: 'eof', write: false,
  });
  const pkg = JSON.parse(readFileSync(join(source, 'package.json'), 'utf8'));
  rmSync(join(destination, 'dist'), { recursive: true, force: true });
  mkdirSync(join(destination, 'dist'), { recursive: true });
  writeFileSync(join(destination, 'dist/index.js'), result.outputFiles[0].contents);
  delete pkg.types;
  delete pkg.typesVersions;
  pkg.exports = { '.': './dist/index.js', './package.json': './package.json' };
  pkg.main = './dist/index.js';
  pkg.cindertraceRuntimeExports = JOSE_RUNTIME_EXPORTS;
  writeFileSync(join(destination, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
}
