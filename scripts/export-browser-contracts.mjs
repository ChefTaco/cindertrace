// Export immutable public contract blobs; local state and backend source excluded.
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
export function exportBrowserContracts(root,output) {
 const git=args=>execFileSync('git',['--no-replace-objects',...args],{cwd:root});
 const revision=git(['rev-parse','--verify','HEAD^{commit}']).toString().trim();
 const names=['index.ts','lab.ts','browser-auth.ts','browser.ts'];
 const files=names.map(path=>{const source='packages/contracts/src/'+path,bytes=git(['show',revision+':'+source]);
  for(const match of bytes.toString().matchAll(/from\s+['"]([^'"]+)['"]/gu))if(match[1]!=='zod'&&!names.some(name=>'./'+name.replace(/\.ts$/u,'.js')===match[1]))throw Error('Browser contract imports server implementation');
  return{path,source,bytes,sha256:createHash('sha256').update(bytes).digest('hex')};});
 mkdirSync(output,{mode:0o700});
 for(const file of files)writeFileSync(join(output,file.path),file.bytes,{flag:'wx',mode:0o600});
 const manifest={schema:1,product:'cindertrace-browser',version:1,repository:'https://github.com/ChefTaco/cindertrace',revision,files:files.map(({path,source,sha256})=>({path,source,sha256}))};
 writeFileSync(join(output,'provenance.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 const index=process.argv.indexOf('--output');if(index<0||!process.argv[index+1])throw Error('--output NEW_DIRECTORY required');
 exportBrowserContracts(fileURLToPath(new URL('../',import.meta.url)),resolve(process.argv[index+1]));
}
