import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,copyFileSync,writeFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {execFileSync,spawnSync} from 'node:child_process';
test('workspace scans omit private recovery state while exact staged and publication scans still reject it',()=>{
 const root=mkdtempSync(join(tmpdir(),'cinder-privacy-fixture-'));
 try{
  mkdirSync(join(root,'scripts'));for(const name of ['check-private.mjs','privacy-policy.mjs'])copyFileSync(new URL('./'+name,import.meta.url),join(root,'scripts',name));
  execFileSync('git',['init','--quiet',root]);mkdirSync(join(root,'.cindertrace','upgrades'),{recursive:true});writeFileSync(join(root,'.cindertrace','upgrades','receipt.json'),JSON.stringify({synthetic:true}));
  const check=(args=[])=>spawnSync(process.execPath,[join(root,'scripts/check-private.mjs'),...args],{cwd:root,encoding:'utf8'});
  assert.equal(check().status,0,'Ignored local recovery state is kept outside source publication');
  mkdirSync(join(root,'payload','.cindertrace'),{recursive:true});writeFileSync(join(root,'payload','.cindertrace','receipt.json'),JSON.stringify({synthetic:true}));
  assert.notEqual(check(['--artifact',join(root,'payload')]).status,0,'Publication payloads must reject recovery state');
  execFileSync('git',['add','.cindertrace/upgrades/receipt.json'],{cwd:root});
  assert.notEqual(check(['--staged']).status,0,'An exact staged recovery path is always rejected');
  assert.notEqual(check().status,0,'A workspace scan also checks its exact staged index');
 }finally{rmSync(root,{recursive:true,force:true});}
});
