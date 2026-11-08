#!/usr/bin/env python3
"""Fail-closed online file capture. Never stops or writes to source services."""
import hashlib, json, os, pathlib, shutil, sqlite3, stat, subprocess, sys, tarfile, tempfile, time
HOME = pathlib.Path('/home/meshtool')
SEAT = pathlib.Path('/var/lib/docker/volumes/seat-rivet-data/_data')
ROOTS = {'seat': SEAT, **{p: HOME/p for p in ('projects','frank-deck-work','seat-spike','shared','own-rails-staging','own-rails-backup')}}
EXCLUDE = {'node_modules', '.cache', '__pycache__', 'Cache', 'Code Cache', 'GPUCache', 'DawnGraphiteCache', 'DawnWebGPUCache', 'ShaderCache', 'GrShaderCache'}
VOLATILE = {'SingletonLock','SingletonSocket','SingletonCookie','DevToolsActivePort'}
def digest(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def walk(root):
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:]=sorted(d for d in dirs if d not in EXCLUDE)
        for n in list(dirs):
            if (pathlib.Path(base)/n).is_symlink(): files.append(n); dirs.remove(n)
        for n in sorted(files):
            if n not in VOLATILE: yield pathlib.Path(base)/n

def capture(out):
    os.umask(0o077)
    if out.exists(): raise RuntimeError('destination_exists')
    if shutil.disk_usage(HOME).free < 4*1024**3: raise RuntimeError('low_disk')
    for root in ROOTS.values():
        if not root.is_dir(): raise RuntimeError('missing_required_root')
    # Bind target must be the inspected persistent seat volume.
    mounts=json.loads(subprocess.check_output(['docker','inspect','seat-rivet','--format','{{json .Mounts}}']))
    if not any(m['Source']==str(SEAT) and m['Destination']=='/data' for m in mounts): raise RuntimeError('seat_mount_changed')
    with tempfile.TemporaryDirectory(prefix='capture-', dir=out.parent) as tmp:
        dest=pathlib.Path(tmp); entries=[]; directories=[]; checks=[]; ignored=0; dbs=set()
        for label,root in ROOTS.items():
            for base, dirs, _ in os.walk(root,followlinks=False):
                dirs[:]=[d for d in dirs if d not in EXCLUDE and not (pathlib.Path(base)/d).is_symlink()]
                srcdir=pathlib.Path(base); rel=pathlib.Path(label)/srcdir.relative_to(root); meta=srcdir.stat()
                (dest/rel).mkdir(parents=True,exist_ok=True)
                directories.append({'path':str(rel),'uid':meta.st_uid,'gid':meta.st_gid,'mode':stat.S_IMODE(meta.st_mode)})
            paths=list(walk(root))
            for src in paths:
                if src.is_file() and not src.is_symlink():
                    with src.open('rb') as f:
                        if f.read(16)==b'SQLite format 3\x00': dbs.add(src)
            for src in paths:
                rel=pathlib.Path(label)/src.relative_to(root); dst=dest/rel
                if any(str(src)==str(db)+suffix for db in dbs for suffix in ('-wal','-shm','-journal')): ignored+=1; continue
                mode=src.lstat().st_mode
                if stat.S_ISSOCK(mode): ignored+=1; continue
                dst.parent.mkdir(parents=True,exist_ok=True)
                if src.is_symlink():
                    target=os.readlink(src); dst.symlink_to(target); os.lchown(dst,src.lstat().st_uid,src.lstat().st_gid)
                    entries.append({'path':str(rel),'link':target,'uid':src.lstat().st_uid,'gid':src.lstat().st_gid}); checks.append((src,'link',target)); continue
                if not stat.S_ISREG(mode): raise RuntimeError('unsupported_special_file')
                if src in dbs:
                    # SQLite's online backup includes committed WAL data without mutating the source.
                    a=sqlite3.connect(src.as_uri()+'?mode=ro',uri=True,timeout=2)
                    b=sqlite3.connect(dst)
                    kind='sqlite-online'
                    try:
                        deadline=time.monotonic()+5
                        def progress(*_):
                            if time.monotonic()>deadline: raise RuntimeError('sqlite_locked')
                        a.backup(b,pages=128,progress=progress,sleep=.05)
                    except (sqlite3.OperationalError, RuntimeError):
                        a.close(); b.close()
                        # Some Chromium stores hold a lock for the browser lifetime.
                        # Copy DB + journals with before/after hash equality, recover ONLY that copy.
                        with tempfile.TemporaryDirectory(prefix='sqlite-',dir=out.parent) as dbtmp:
                            copy=pathlib.Path(dbtmp)/src.name
                            family=[pathlib.Path(str(src)+x) for x in ('','-wal','-journal') if pathlib.Path(str(src)+x).exists()]
                            hashes={p:digest(p) for p in family}
                            for p in family: shutil.copyfile(p,pathlib.Path(dbtmp)/p.name)
                            if any(digest(p)!=h or digest(pathlib.Path(dbtmp)/p.name)!=h for p,h in hashes.items()): raise RuntimeError('sqlite_family_changed')
                            if family!=[pathlib.Path(str(src)+x) for x in ('','-wal','-journal') if pathlib.Path(str(src)+x).exists()]: raise RuntimeError('sqlite_journal_changed')
                            a=sqlite3.connect(copy); b=sqlite3.connect(dst)
                            try:
                                if a.execute('pragma integrity_check').fetchall()!=[('ok',)]: raise RuntimeError('sqlite_copy_integrity')
                                a.backup(b)
                            finally: a.close(); b.close()
                            checks.extend((p,'file',h) for p,h in hashes.items())
                        kind='sqlite-stable-recovered-copy'
                    finally: a.close(); b.close()
                    with sqlite3.connect(dst) as verified:
                        if verified.execute('PRAGMA integrity_check').fetchall()!=[('ok',)]: raise RuntimeError('sqlite_integrity')
                else:
                    before=digest(src); shutil.copyfile(src,dst)
                    if digest(dst)!=before or digest(src)!=before: raise RuntimeError('source_changed_retry_required')
                    checks.append((src,'file',before)); kind='stable-file'
                os.chmod(dst,stat.S_IMODE(mode)); os.chown(dst,src.stat().st_uid,src.stat().st_gid)
                entries.append({'path':str(rel),'sha256':digest(dst),'bytes':dst.stat().st_size,'uid':dst.stat().st_uid,'gid':dst.stat().st_gid,'mode':stat.S_IMODE(mode),'method':kind})
            # Detect additions/deletions during the copy, including multi-file LevelDB churn.
            if {str(p) for p in walk(root)} != {str(p) for p in paths}: raise RuntimeError('tree_changed_retry_required')
        for src,kind,value in checks:
            if (os.readlink(src) if kind=='link' else digest(src))!=value: raise RuntimeError('source_changed_retry_required')
        # OpenShell's work is in a writable container layer, not a volume.
        names=subprocess.check_output(['docker','ps','--format','{{.Names}}'],text=True).splitlines()
        seats=[n for n in names if n.startswith('openshell-default--mesh-seat-') and not n.endswith('-supervisor')]
        if len(seats)!=1: raise RuntimeError('openshell_seat_inventory_changed')
        c=seats[0]; osdir=dest/'openshell-workspace'; osdir.mkdir()
        # Reading twice and requiring identical bytes detects a moving container workspace.
        args=['docker','exec',c,'tar','--sort=name','-C','/','-cf','-','sandbox','home/ubuntu']
        first=subprocess.check_output(args); second=subprocess.check_output(args)
        if first!=second: raise RuntimeError('openshell_workspace_changed')
        p=osdir/'workspace.tar'; p.write_bytes(first)
        entries.append({'path':'openshell-workspace/workspace.tar','sha256':digest(p),'bytes':len(first),'mode':0o600,'method':'double-read-container-tar'})
        for d in reversed(directories):
            os.chown(dest/d['path'],d['uid'],d['gid']); os.chmod(dest/d['path'],d['mode'])
        manifest={'version':2,'directories':directories,'roots':list(ROOTS),'exclusions':sorted(EXCLUDE|VOLATILE),'ignoredSocketsAndSqliteSidecars':ignored,'entries':entries,'openshell':c,'consistency':'stable per-file + SQLite online backups; not an atomic cross-application transaction'}
        (dest/'manifest.json').write_text(json.dumps(manifest))
        with tarfile.open(out,'w:gz') as tar:
            for child in sorted(dest.iterdir()): tar.add(child,arcname=child.name,recursive=True)
    os.chmod(out,0o600)
    print(json.dumps({'files':len(entries),'sqlite':sum(x.get('method','').startswith('sqlite-') for x in entries),'archiveBytes':out.stat().st_size,'archiveSha256':digest(out)}))
if __name__=='__main__':
    try: capture(pathlib.Path(sys.argv[1]))
    except Exception as e: print(json.dumps({'error':type(e).__name__,'reason':str(e) if isinstance(e,RuntimeError) else 'capture_failed'}),file=sys.stderr); sys.exit(1)
