"""Real encrypted backup API, offline exclusion, negative auth and restored HTTP."""
from pathlib import Path
import json
import os
import secrets
import socket
import sqlite3
import sys
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'app'))
sys.path.insert(0,str(ROOT/'tests/ft10'))
from test_candidate_workflow import FakeClamd,ScannerHandler,run_cli,serving,Fields
import candidate_backup as backup
import secure_backup
from candidate_runtime import read_config,acquire_lifecycle


def main():
    import httpx
    checks=0
    def check(ok,label):
        nonlocal checks
        assert ok,label
        checks+=1;print('PASS: '+label,flush=True)
    with tempfile.TemporaryDirectory(prefix='FT11_SYNTHETIC_BACKUP_') as folder:
        root=Path(folder);data=root/'source';restored=root/'restored';archive=root/'candidate.ppbk'
        with FakeClamd(('127.0.0.1',0),ScannerHandler) as scanner:
            thread=threading.Thread(target=scanner.serve_forever,daemon=True);thread.start()
            try:
                check(run_cli('init','--data-dir',str(data),'--scanner-port',str(scanner.server_address[1]),'--confirm-synthetic-only').returncode==0,'fresh store initialized for offline backup test')
                accounts=json.loads((data/'synthetic-accounts.json').read_text())['accounts']
                key=secrets.token_urlsafe(32)
                with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                with httpx.Client(base_url=f'http://127.0.0.1:{port}',trust_env=False,timeout=10,follow_redirects=False) as client:
                    with serving(data,port,root/'first.log'):
                        account=accounts[1]
                        client.get('/login');token=client.cookies.get('login_csrf')
                        check(client.post('/login',data={**{k:account[k] for k in ('username','password')},'login_token':token}).status_code==303,'synthetic patient session created before backup')
                        try:backup.create(data,archive,key)
                        except Exception:check(not archive.exists(),'backup is refused while normal candidate processes are serving')
                        else:raise AssertionError('live backup accepted')
                    _,config=read_config(data)
                    guard=acquire_lifecycle(data,config['instance_id'])
                    try:
                        try:backup.create(data,archive,key)
                        except Exception:check(not archive.exists(),'an active worker-style shared lease also excludes offline backup')
                        else:raise AssertionError('active worker lease ignored')
                    finally:guard.close()
                    count=backup.create(data,archive,key)
                    check(count==5 and archive.is_file(),'encrypted archive includes SQLite, PDF, marker, stable secret and synthetic account file')
                    for name in ('wrong-key','tampered'):
                        target=root/name
                        source=archive
                        passphrase=secrets.token_urlsafe(32) if name=='wrong-key' else key
                        if name=='tampered':
                            source=root/'tampered.ppbk';payload=bytearray(archive.read_bytes());payload[-1]^=1;source.write_bytes(payload)
                        try:backup.restore(source,target,passphrase)
                        except Exception:check(not target.exists(),'unauthenticated '+name+' restore never publishes a store')
                        else:raise AssertionError('unauthenticated restore accepted')
                    count=backup.restore(archive,restored,key)
                    check(count==5 and read_config(restored)[1]==config,'authenticated restore validates candidate schema/marker/gate')
                    check(all((data/name).read_bytes()==(restored/name).read_bytes() for name in ('candidate-secret','candidate.json','synthetic-accounts.json')),'stable identity and local synthetic credentials preserved by encryption roundtrip')
                    check((restored/'shared-admission/total/slot-0').exists() and (restored/'candidate-lifecycle.sqlite3').exists(),'runtime admission/lifecycle guards freshly recreated after restore')
                    before=(restored/'candidate.sqlite3').read_bytes()
                    try:backup.restore(archive,restored,key)
                    except Exception:check((restored/'candidate.sqlite3').read_bytes()==before,'restore refuses existing destination without overwrite')
                    else:raise AssertionError('existing restore overwritten')
                    with serving(restored,port,root/'restored.log'):
                        check(client.get('/dashboard').status_code==200,'restored normal candidate accepts pre-backup session')
                        check(client.get('/reports/1/download').status_code==423,'restored unattested legacy report keeps AV hold')
                    # Legacy API retains its original member allowlist and format.
                    plain=root/'legacy.ppbk'
                    with backup.source_environment(data):secure_backup.create_backup(plain,key)
                    check(secure_backup.verify_or_restore(plain,key)==2,'legacy DB/PDF-only encrypted backup remains compatible')
                    try:secure_backup.verify_or_restore(archive,key,root/'legacy-refusal')
                    except Exception:check(not (root/'legacy-refusal').exists(),'legacy restore does not silently accept candidate metadata')
                    else:raise AssertionError('legacy member allowlist broadened by default')
            finally:scanner.shutdown();thread.join(timeout=3)
    (ROOT/'reports/last_candidate_backup.json').write_text(json.dumps({'checks_passed':checks,
        'mode':'SYNTHETIC OFFLINE AES-GCM / RESTORED NORMAL HTTP','production_approved':False,'release_gate':'HOLD / NO-GO'},indent=2))
    print(f'PASS: FT11 OFFLINE CANDIDATE BACKUP ({checks} checks). HOLD / NO-GO.')


if __name__=='__main__':main()
