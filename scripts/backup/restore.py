#!/usr/bin/env python3
"""Read backup from stdin, restore only below a new private proof directory."""
import gzip, hashlib, io, json, os, pathlib, sqlite3, stat, subprocess, sys, tarfile, time, uuid
BASE=pathlib.Path('/home/meshtool/own-rails-backups')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def extract(data,dest):
    dest.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as t:
        members=t.getmembers(); seen=set(); links=set()
        for m in members:
            p=pathlib.PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or m.name in seen: raise RuntimeError('unsafe_archive_path')
            seen.add(m.name)
            if not (m.isdir() or m.isfile() or m.issym()): raise RuntimeError('unsafe_archive_type')
            if m.issym(): links.add(p)
        for m in members:
            p=pathlib.PurePosixPath(m.name)
            if any(parent in links for parent in p.parents): raise RuntimeError('symlink_parent')
        for m in members:
            target=dest/m.name
            target.parent.mkdir(parents=True,exist_ok=True)
            if m.isdir(): target.mkdir(exist_ok=True)
            elif m.isfile():
                with target.open('xb') as f: f.write(t.extractfile(m).read())
                target.chmod(m.mode & 0o777)
                if os.geteuid()==0: os.chown(target,m.uid,m.gid)
        for m in members:
            if m.issym():
                (dest/m.name).symlink_to(m.linkname)
                if os.geteuid()==0: os.lchown(dest/m.name,m.uid,m.gid)
        for m in reversed(members):
            if m.isdir():
                (dest/m.name).chmod(m.mode & 0o777)
                if os.geteuid()==0: os.chown(dest/m.name,m.uid,m.gid)
def verify(root):
    manifest=json.loads((root/'manifest.json').read_text()); count=0; sqlite_count=0
    for e in manifest['entries']:
        p=root/e['path']
        if 'uid' in e and (p.lstat().st_uid,p.lstat().st_gid)!=(e['uid'],e['gid']): raise RuntimeError('ownership_mismatch')
        if 'mode' in e and stat.S_IMODE(p.lstat().st_mode)!=e['mode']: raise RuntimeError('mode_mismatch')
        if 'link' in e:
            if not p.is_symlink() or os.readlink(p)!=e['link']: raise RuntimeError('link_mismatch')
        else:
            if p.is_symlink() or not p.is_file() or sha(p)!=e['sha256']: raise RuntimeError('file_mismatch')
            count+=1
            if e['method'].startswith('sqlite-'):
                with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as c:
                    if c.execute('pragma integrity_check').fetchall()!=[('ok',)]: raise RuntimeError('sqlite_integrity')
                sqlite_count+=1
    for d in manifest.get('directories',[]):
        p=root/d['path']; st=p.stat()
        if not p.is_dir() or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(d['uid'],d['gid'],d['mode']): raise RuntimeError('directory_metadata_mismatch')
    for n in ('memory.json','storage.json','sessions.json','projects.json'): json.loads((root/'seat'/n).read_text())
    # Negative control: a missing file must make the same verifier reject the restore.
    return count,sqlite_count
BROWSER=r'''
const fs=require('fs'), {chromium}=require('playwright');
(async()=>{
fs.cpSync('/proof/profile','/tmp/profile',{recursive:true});
const saved=JSON.parse(fs.readFileSync('/proof/storage.json'));
const memory=JSON.parse(fs.readFileSync('/proof/memory.json'));
if(process.getuid()!==1000)throw Error('unexpected_seat_identity');
fs.mkdirSync('/tmp/home');process.env.HOME='/tmp/home';
const ctx=await chromium.launchPersistentContext('/tmp/profile',{headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
await ctx.route('**/*',r=>r.abort());
if(saved.cookies?.length) await ctx.addCookies(saved.cookies);
const cookies=await ctx.cookies();
const expected=(saved.cookies||[]).filter(c=>c.expires<=0||c.expires>Date.now()/1000);
if(!expected.every(e=>cookies.some(c=>c.name===e.name&&c.domain===e.domain&&c.path===e.path&&c.value===e.value)))throw Error('cookie_restore_mismatch');
await ctx.close();
console.log(JSON.stringify({browserProfileOpened:true,browserUid:process.getuid(),savedCookiesRestored:expected.length,memoryJsonReadable:!!memory}));
})().catch(()=>{console.error('browser_restore_failed');process.exit(1)});
'''
def main():
    os.umask(0o077); run='restore-proof-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+uuid.uuid4().hex[:8]
    dest=BASE/run; blob=sys.stdin.buffer.read(); extract(blob,dest)
    for line in (dest/'SHA256SUMS').read_text().splitlines():
        h,n=line.split(None,1); n=n.lstrip('*')
        if '/' in n or n.startswith('.'): raise RuntimeError('unsafe_checksum_name')
        if sha(dest/n)!=h: raise RuntimeError('outer_checksum_mismatch')
    root=dest/'restored'; extract((dest/'seat-workspace.tar.gz').read_bytes(),root)
    files,dbs=verify(root)
    m=root/'seat/memory.json'; old=m.read_bytes(); m.write_bytes(old+b' ')
    try:
        try: verify(root)
        except RuntimeError: negative=True
        else: raise RuntimeError('negative_control_did_not_fail')
    finally: m.write_bytes(old)
    verify(root)
    # Unpack OpenShell workspaces only into this new proof directory, never a live container.
    # New-format backups hold one workspace per seat at openshell-workspace/<label>/workspace.tar
    # (manifest 'openshell' is a dict label -> container); old backups hold a single workspace
    # at openshell-workspace/workspace.tar.
    manifest = json.loads((root/'manifest.json').read_text())
    seats = manifest.get('openshell')
    restored_seats = {}
    if isinstance(seats, dict) and seats:
        (dest/'openshell-restored').mkdir(mode=0o700)
        for label in sorted(seats):
            data = (root/'openshell-workspace'/label/'workspace.tar').read_bytes()
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as t:
                restored_seats[label] = len(t.getmembers())
            extract(data, dest/'openshell-restored'/label)
    elif (root/'openshell-workspace'/'workspace.tar').exists():
        data = (root/'openshell-workspace'/'workspace.tar').read_bytes()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as t:
            restored_seats['legacy'] = len(t.getmembers())
        extract(data, dest/'openshell-restored')
    else:
        raise RuntimeError('openshell_workspace_missing')
    b=subprocess.run(['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','768m','--cpus','1','--user','1000:1000','--tmpfs','/tmp:rw,size=256m','--mount',f'type=bind,src={root / "seat"},dst=/proof,readonly','--entrypoint','node','seat-spike:0.1','-e',BROWSER],capture_output=True,timeout=90)
    if b.returncode: raise RuntimeError('isolated_browser_failed')
    browser=json.loads(b.stdout)
    name='backup-proof-'+uuid.uuid4().hex[:12]
    subprocess.run(['docker','run','-d','--name',name,'--network','none','--memory','512m','--cpus','1','--tmpfs','/var/lib/postgresql:rw,size=256m','--tmpfs','/var/run/postgresql:rw,size=16m','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=runtime','-e','POSTGRES_DB=runtime_staging','postgres:18'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            if subprocess.run(['docker','exec',name,'pg_isready','-U','runtime'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0: break
            time.sleep(.5)
        else: raise RuntimeError('isolated_postgres_not_ready')
        sql=gzip.decompress((dest/'runtime_staging.sql.gz').read_bytes())
        r=subprocess.run(['docker','exec','-i',name,'psql','-v','ON_ERROR_STOP=1','-U','runtime','-d','runtime_staging'],input=sql,capture_output=True,timeout=90)
        if r.returncode: raise RuntimeError('isolated_postgres_restore_failed')
        tables=int(subprocess.check_output(['docker','exec',name,'psql','-At','-U','runtime','-d','runtime_staging','-c',"select count(*) from information_schema.tables where table_schema='public'"]))
        if tables<1: raise RuntimeError('empty_database_restore')
    finally:
        subprocess.run(['docker','rm','-f',name],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    receipt={'restoreDirectory':str(dest),'filesVerified':files,'sqliteIntegrityChecks':dbs,'ownershipAndModesVerified':True,'tamperNegativeControl':negative,'postgresTablesRestored':tables,'openshellSeatsRestored':restored_seats,**browser,'network':'none','liveServicesTouched':False}
    (dest/'RESTORE-VERIFIED.json').write_text(json.dumps(receipt,indent=2)); print(json.dumps(receipt))
if __name__=='__main__':
    try: main()
    except Exception as e: print(json.dumps({'error':type(e).__name__,'reason':str(e) if isinstance(e,RuntimeError) else 'restore_failed'}),file=sys.stderr); sys.exit(1)
