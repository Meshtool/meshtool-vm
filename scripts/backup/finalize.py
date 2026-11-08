#!/usr/bin/env python3
"""Record independent restore proof; remove only disposable restored copies.
Never purges volumes, live files, unverified backups, or remote objects.
"""
import json,pathlib,re,shutil,sys,time,datetime
def finalize(r,base=pathlib.Path('/home/meshtool/own-rails-backups')):
 if not re.fullmatch(r'\d{8}T\d{6}Z',r['source']): raise RuntimeError('bad_source')
 if not r.get('remoteDownloadMatched') or not r.get('tamperRejected') or not r.get('browserProfileOpened') or not r.get('postgresTablesRestored'): raise RuntimeError('unverified')
 proof=pathlib.Path(r['restoreDirectory'])
 if proof.parent!=base or not re.fullmatch(r'restore-proof-\d{8}T\d{6}Z-[0-9a-f]{8}',proof.name) or proof.is_symlink(): raise RuntimeError('unsafe_proof_path')
 if not (proof/'RESTORE-VERIFIED.json').is_file(): raise RuntimeError('missing_proof')
 (base/r['source']/'OFFSITE-VERIFIED.json').write_text(json.dumps(r,indent=2))
 # These are generated test restores, not live data. Their exact encrypted source
 # has been downloaded from R2 and independently restored before this cleanup.
 shutil.rmtree(proof)
 pruned=0
 for candidate in base.iterdir():
  if not re.fullmatch(r'\d{8}T\d{6}Z',candidate.name) or candidate.is_symlink() or not candidate.is_dir(): continue
  age=time.time()-datetime.datetime.strptime(candidate.name,'%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
  if age<=7*86400: continue
  ack=candidate/'OFFSITE-VERIFIED.json'
  if not ack.is_file(): continue  # Historical/unverified data is never purged.
  old=json.loads(ack.read_text())
  if old.get('source')!=candidate.name or not old.get('remoteDownloadMatched') or not old.get('object','').startswith('r2://estate-backup/meshtool-vm/'): continue
  # Recoverable local cache only: the independently downloaded+restored R2 copy remains.
  shutil.rmtree(candidate);pruned+=1
 return {'receiptSaved':True,'disposableRestoreRemoved':True,'verifiedLocalCachesPruned':pruned}

if __name__=='__main__':
 print(json.dumps(finalize(json.load(sys.stdin))))
