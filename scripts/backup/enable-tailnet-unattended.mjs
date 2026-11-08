// Prepared for explicit approval: one preference only; never restart/logout/up/reset.
import {spawnSync} from 'node:child_process';
import {writeFileSync} from 'node:fs';
const exe='C:/Program Files/Tailscale/tailscale.exe';
const call=args=>{const r=spawnSync(exe,args,{encoding:'utf8',timeout:30000});if(r.status!==0)throw Error('tailscale_command_failed');return r.stdout;};
try{
 const before=JSON.parse(call(['debug','prefs'])), state=JSON.parse(call(['status','--json']));
 if(state.Self?.OS!=='windows'||state.BackendState!=='Running')throw Error('unexpected_tailnet_state');
 if(!before.ForceDaemon)call(['set','--unattended=true']);
 const after=JSON.parse(call(['debug','prefs'])), next=JSON.parse(call(['status','--json']));
 const changed=[...new Set([...Object.keys(before),...Object.keys(after)])].filter(k=>JSON.stringify(before[k])!==JSON.stringify(after[k]));
 const result={at:new Date().toISOString(),beforeUnattended:!!before.ForceDaemon,afterUnattended:!!after.ForceDaemon,changedPreferenceKeys:changed,sameNode:state.Self.ID===next.Self.ID,backendRunning:next.BackendState==='Running',noRestartCommandUsed:true};
 result.ok=result.afterUnattended&&result.sameNode&&result.backendRunning&&changed.every(k=>k==='ForceDaemon');
 writeFileSync('C:/backups/meshtool-recovery/tailnet-unattended-proof.json',JSON.stringify(result,null,2));
 console.log(JSON.stringify(result));if(!result.ok)process.exitCode=1;
}catch(e){console.error(JSON.stringify({error:e.message}));process.exitCode=1;}
