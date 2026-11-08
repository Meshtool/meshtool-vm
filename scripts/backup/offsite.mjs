// Windows host runner: encrypted bytes only on disk or R2. Never logs credentials.
import {loadCredentials} from 'file:///C:/Users/vipth/trust-layer/hooks/vault-guard.mjs';
import {encrypt,decrypt} from 'file:///C:/projects/_hq/ops/estate-backup.mjs';
import {spawnSync} from 'node:child_process';
import {mkdirSync,readFileSync,writeFileSync,existsSync,rmSync} from 'node:fs';
import {createHash} from 'node:crypto';
const DIR='C:/backups/meshtool-recovery';
const SSH='C:/Windows/System32/OpenSSH/ssh.exe';
const WRANGLER='C:/Users/vipth/AppData/Roaming/npm/node_modules/wrangler/bin/wrangler.js';
const hash=b=>createHash('sha256').update(b).digest('hex');
function run(exe,args,opts={}) {
 const r=spawnSync(exe,args,{maxBuffer:1024*1024*1024,timeout:300000,...opts});
 if(r.status!==0) throw new Error(`step_failed:${exe===SSH?'ssh':'r2'}:status=${r.status}`);
 return r.stdout;
}
const ssh=(command,input)=>run(SSH,['-o','BatchMode=yes','-o','ConnectTimeout=15','meshtool',command],input?{input}:{});
try {
 mkdirSync(DIR,{recursive:true});
 const creds=loadCredentials();
 const get=k=>creds.filter(c=>c.name===k).at(-1)?.val;
 const pass=get('ESTATE_BACKUP_PASSPHRASE'), token=get('CLOUDFLARE_API_TOKEN');
 if(!pass||!token) throw Error('required_vault_key_missing');
 const stamp=ssh('cat /home/meshtool/own-rails-backups/LATEST').toString().trim();
 if(!/^\d{8}T\d{6}Z$/.test(stamp)) throw Error('invalid_latest');
 const sourceTime=Date.parse(stamp.replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/,'$1-$2-$3T$4:$5:$6Z'));
 if(Date.now()-sourceTime>48*3600000)throw Error('latest_backup_older_than_48_hours');
 const receiptFile=`${DIR}/${stamp}.verified.json`;
 if(existsSync(receiptFile)&&!process.argv.includes('--force-verify')) {writeFileSync(`${DIR}/last-run.json`,JSON.stringify({ok:true,at:new Date().toISOString(),alreadyVerified:stamp}));console.log(JSON.stringify({alreadyVerified:stamp}));process.exit(0);}
 const remote=`/home/meshtool/own-rails-backups/${stamp}`;
 const local=`${DIR}/${stamp}.enc`, downloaded=`${DIR}/${stamp}.download.enc`;
 const plain=existsSync(local)?decrypt(readFileSync(local),pass):ssh(`cd ${remote} && test -f COMPLETE && sha256sum -c SHA256SUMS >/dev/null && tar -czf - runtime_staging.sql.gz seat-workspace.tar.gz capture-receipt.json containers.txt staging-health.json disk.txt SHA256SUMS COMPLETE`);
 const encrypted=existsSync(local)?readFileSync(local):encrypt(plain,pass);
 if(hash(decrypt(encrypted,pass))!==hash(plain)) throw Error('crypto_roundtrip_failed');
 const bad=Buffer.from(encrypted); bad[bad.length-1]^=1;
 let tamper=false,wrongKey=false;
 try{decrypt(bad,pass)}catch{tamper=true}
 try{decrypt(encrypted,pass+'wrong-key-control')}catch{wrongKey=true}
 if(!tamper||!wrongKey) throw Error('crypto_negative_control_failed');
 if(!existsSync(local)) writeFileSync(local,encrypted,{flag:'wx'});
 const key=`estate-backup/meshtool-vm/${stamp}-${hash(encrypted).slice(0,16)}.enc`;
 const env={...process.env,CLOUDFLARE_API_TOKEN:token};
 const parts=[]; const downloadedParts=[];
 for(let offset=0,index=0;offset<encrypted.length;offset+=100*1024*1024,index++) {
  const bytes=encrypted.subarray(offset,Math.min(offset+100*1024*1024,encrypted.length));
  const suffix=`.part${String(index).padStart(3,'0')}`, object=key+suffix;
  const partFile=local+suffix, getFile=downloaded+suffix;
  writeFileSync(partFile,bytes);
  if(!process.argv.includes('--reuse-downloads')) {
   run(process.execPath,[WRANGLER,'r2','object','put',object,'--file',partFile,'--remote'],{env});
   run(process.execPath,[WRANGLER,'r2','object','get',object,'--file',getFile,'--remote'],{env});
  }
  const fetchedPart=readFileSync(getFile);
  if(hash(fetchedPart)!==hash(bytes))throw Error('part_download_mismatch');
  downloadedParts.push(fetchedPart);parts.push({object,bytes:bytes.length,sha256:hash(bytes)});
  console.log(JSON.stringify({encryptedPartVerified:index+1,partsTotal:Math.ceil(encrypted.length/(100*1024*1024))}));
 }
 const descriptor={format:'ESTBAK01-split-v1',encryptedBytes:encrypted.length,sha256:hash(encrypted),parts};
 const manifestFile=local+'.manifest.json', manifestGet=downloaded+'.manifest.json';
 writeFileSync(manifestFile,JSON.stringify(descriptor));
 if(!process.argv.includes('--reuse-downloads')) {
  run(process.execPath,[WRANGLER,'r2','object','put',key+'.manifest.json','--file',manifestFile,'--remote'],{env});
  run(process.execPath,[WRANGLER,'r2','object','get',key+'.manifest.json','--file',manifestGet,'--remote'],{env});
 }
 if(hash(readFileSync(manifestFile))!==hash(readFileSync(manifestGet)))throw Error('remote_manifest_mismatch');
 const fetched=Buffer.concat(downloadedParts);
 if(hash(fetched)!==hash(encrypted)) throw Error('remote_ciphertext_mismatch');
 const restored=decrypt(fetched,pass);
 if(hash(restored)!==hash(plain)) throw Error('remote_plaintext_mismatch');
 const proof=JSON.parse(ssh('sudo -n python3 /home/meshtool/own-rails-backup/restore.py',restored).toString());
 const receipt={verifiedAt:new Date().toISOString(),source:stamp,object:`r2://${key}.manifest.json`,parts:parts.length,encryptedBytes:encrypted.length,encryptedSha256:hash(encrypted),remoteDownloadMatched:true,wrongKeyRejected:wrongKey,tamperRejected:tamper,...proof};
 writeFileSync(receiptFile,JSON.stringify(receipt,null,2));
 writeFileSync(`${DIR}/latest-verified.json`,JSON.stringify(receipt,null,2));
 ssh('sudo -n python3 /home/meshtool/own-rails-backup/finalize.py',Buffer.from(JSON.stringify(receipt)));
 for(let i=0;i<parts.length;i++){const suffix=`.part${String(i).padStart(3,'0')}`;rmSync(local+suffix);rmSync(downloaded+suffix);}
 writeFileSync(`${DIR}/last-run.json`,JSON.stringify({ok:true,at:new Date().toISOString(),source:stamp}));
 console.log(JSON.stringify(receipt));
} catch(e) {writeFileSync(`${DIR}/last-run.json`,JSON.stringify({ok:false,at:new Date().toISOString(),error:e.message}));console.error(JSON.stringify({error:e.message}));process.exitCode=1;}
