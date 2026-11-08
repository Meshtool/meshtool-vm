import importlib.util, io, pathlib, sqlite3, tarfile, tempfile, unittest, json
HERE=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('restore',HERE/'restore.py'); restore=importlib.util.module_from_spec(spec); spec.loader.exec_module(restore)
class RestoreSafety(unittest.TestCase):
 def archive(self, entries):
  out=io.BytesIO()
  with tarfile.open(fileobj=out,mode='w') as t:
   for name,kind,value in entries:
    m=tarfile.TarInfo(name)
    if kind=='link': m.type=tarfile.SYMTYPE;m.linkname=value;t.addfile(m)
    else: data=value.encode();m.size=len(data);t.addfile(m,io.BytesIO(data))
  return out.getvalue()
 def test_traversal_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(RuntimeError): restore.extract(self.archive([('../escape','file','no')]),pathlib.Path(d)/'out')
   self.assertFalse((pathlib.Path(d)/'escape').exists())
 def test_symlink_parent_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(RuntimeError): restore.extract(self.archive([('link','link','/tmp'),('link/escape','file','no')]),pathlib.Path(d)/'out')
 def test_duplicate_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(RuntimeError): restore.extract(self.archive([('x','file','one'),('x','file','two')]),pathlib.Path(d)/'out')
 def test_regular_file_restores(self):
  with tempfile.TemporaryDirectory() as d:
   out=pathlib.Path(d)/'out';restore.extract(self.archive([('workspace/a','file','saved change')]),out)
   self.assertEqual((out/'workspace/a').read_text(),'saved change')
 def test_sqlite_online_backup_includes_wal(self):
  with tempfile.TemporaryDirectory() as d:
   src=pathlib.Path(d)/'live.db';dst=pathlib.Path(d)/'copy.db'
   with sqlite3.connect(src) as writer:
    writer.execute('pragma journal_mode=wal');writer.execute('create table marker(v)');writer.execute('insert into marker values (42)');writer.commit()
    with sqlite3.connect(src.as_uri()+'?mode=ro',uri=True) as a,sqlite3.connect(dst) as b:
     a.backup(b);self.assertEqual(b.execute('select v from marker').fetchone(),(42,))
 def test_retention_only_removes_verified_cache(self):
  spec=importlib.util.spec_from_file_location('finalize',HERE/'finalize.py'); mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
  with tempfile.TemporaryDirectory() as d:
   base=pathlib.Path(d);source='20261108T100000Z';(base/source).mkdir()
   proof=base/'restore-proof-20261108T100000Z-12345678';proof.mkdir();(proof/'RESTORE-VERIFIED.json').write_text('{}')
   old=base/'20200101T000000Z';old.mkdir();(old/'OFFSITE-VERIFIED.json').write_text(json.dumps({'source':old.name,'remoteDownloadMatched':True,'object':'r2://estate-backup/meshtool-vm/test.enc'}))
   unverified=base/'20200102T000000Z';unverified.mkdir();(unverified/'irreplaceable').write_text('keep')
   r={'source':source,'remoteDownloadMatched':True,'tamperRejected':True,'browserProfileOpened':True,'postgresTablesRestored':23,'restoreDirectory':str(proof)}
   self.assertEqual(mod.finalize(r,base)['verifiedLocalCachesPruned'],1)
   self.assertFalse(old.exists());self.assertTrue((unverified/'irreplaceable').exists());self.assertTrue((base/source/'OFFSITE-VERIFIED.json').exists())
 def test_cleanup_refuses_nonproof_directory(self):
  spec=importlib.util.spec_from_file_location('finalize',HERE/'finalize.py'); mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
  with tempfile.TemporaryDirectory() as d:
   base=pathlib.Path(d);live=base/'live';live.mkdir()
   r={'source':'20261108T100000Z','remoteDownloadMatched':True,'tamperRejected':True,'browserProfileOpened':True,'postgresTablesRestored':23,'restoreDirectory':str(live)}
   with self.assertRaises(RuntimeError): mod.finalize(r,base)
   self.assertTrue(live.exists())
if __name__=='__main__': unittest.main()
