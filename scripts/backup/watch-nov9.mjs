// Read-only observation of the next existing scheduled execution; never triggers it.
import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
const base='C:/backups/meshtool-recovery', target=Date.parse('2026-11-09T11:00:00Z');
const read=n=>JSON.parse(readFileSync(`${base}/${n}`,'utf8').replace(/^\uFEFF/,''));
const previous=read('latest-verified.json');
const SSH='C:/Windows/System32/OpenSSH/ssh.exe';
function services(){const r=spawnSync(SSH,['-o','BatchMode=yes','-o','IdentityAgent=none','-o','ConnectTimeout=15','meshtool','docker ps -q | xargs -r docker inspect --format \"{{.Name}} {{.State.StartedAt}} {{.RestartCount}}\"'],{encoding:'utf8',timeout:30000});if(r.status!==0)throw Error('service_observation_failed');return r.stdout.trim().split('\n').sort();}
const before=services();
writeFileSync(`${base}/nov9-watch-baseline.json`,JSON.stringify({at:new Date().toISOString(),previous,services:before},null,2));
console.log('Read-only watch active for 2026-11-09T11:00Z');
while(Date.now()<target-60000) await new Promise(resolve=>setTimeout(resolve,60000));
const ps='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe';
const query='$t=Get-ScheduledTask -TaskName meshtool-seat-workspace-backup;$i=Get-ScheduledTaskInfo -TaskName $t.TaskName;[pscustomobject]@{State=$t.State.ToString();LogonType=$t.Principal.LogonType.ToString();LastRunUtc=$i.LastRunTime.ToUniversalTime().ToString("o");LastResult=$i.LastTaskResult;NextRunUtc=$i.NextRunTime.ToUniversalTime().ToString("o")}|ConvertTo-Json -Compress';
while(Date.now()<target+60*60*1000){
 const r=spawnSync(ps,['-NoProfile','-Command',query],{encoding:'utf8',timeout:20000});
 if(r.status!==0)throw Error('scheduler_read_failed');
 const task=JSON.parse(r.stdout);
 if(Date.parse(task.LastRunUtc)>=target&&task.State!=='Running'){
  const last=read('last-run.json'), execution=read('unattended-proof.json'), restore=read('latest-verified.json');
  const freshExecution=Date.parse(execution.startedAt)>=target&&execution.ok&&execution.sessionId===0&&execution.batchLogon&&!execution.userInteractive;
  const freshRestore=Date.parse(restore.verifiedAt)>=target&&restore.source!==previous.source&&/^20261109T/.test(restore.source)&&restore.remoteDownloadMatched===true&&restore.wrongKeyRejected===true&&restore.tamperRejected===true&&restore.filesVerified>0&&restore.sqliteIntegrityChecks===3&&restore.postgresTablesRestored===23&&restore.browserProfileOpened===true&&restore.browserUid===1000&&restore.memoryJsonReadable===true&&restore.network==='none'&&restore.liveServicesTouched===false&&execution.fullVerification===true&&execution.source===restore.source;
  const after=services();
  const unchanged=JSON.stringify(before)===JSON.stringify(after);
  const result={observedAt:new Date().toISOString(),scheduledForUtc:new Date(target).toISOString(),manuallyTriggered:false,liveContainersUnchanged:unchanged,servicesBefore:before,servicesAfter:after,task,scheduledExecutionPassed:task.LastResult===0&&freshExecution&&last.ok&&Date.parse(last.at)>=target,uploadAndRestoreRan:freshRestore,outcome:freshRestore?'fresh_restore':last.alreadyVerified?'already_verified_skip':'no_fresh_restore_evidence',lastRun:last,execution,restore};
  writeFileSync(`${base}/scheduled-watch-20261109.json`,JSON.stringify(result,null,2));
  console.log(JSON.stringify({scheduledExecutionPassed:result.scheduledExecutionPassed,uploadAndRestoreRan:freshRestore,outcome:result.outcome,lastRun:task.LastRunUtc,nextRun:task.NextRunUtc}));
  process.exit(result.scheduledExecutionPassed&&freshRestore&&unchanged?0:1);
 }
 await new Promise(resolve=>setTimeout(resolve,15000));
}
throw Error('scheduled_run_not_completed_by_deadline');
