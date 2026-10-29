"""Shipping CLI + normal candidate entrypoint, real HTTP and fake clamd protocol.

No fixture monkeypatches in workers; no real AV installation or patient data.
"""
from contextlib import contextmanager
import hashlib
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'app'))
from shared_pdf_admission import DiskSlotPool


class FakeClamd(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    verdict='clean'
    scans=0


class ScannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        def exact(n):
            data=bytearray()
            while len(data)<n:
                block=self.request.recv(n-len(data))
                if not block:raise OSError('synthetic scanner EOF')
                data.extend(block)
            return bytes(data)
        try:
            command=bytearray()
            while not command.endswith(b'\0') and len(command)<40:command.extend(exact(1))
            if command!=b'zINSTREAM\0':return
            while size:=struct.unpack('!I',exact(4))[0]:
                while size:
                    chunk=min(size,65536);exact(chunk);size-=chunk
            self.server.scans+=1
            reply={'clean':b'stream: OK\0','found':b'stream: Synthetic-Only FOUND\0',
                   'error':b'stream: ERROR\0'}[self.server.verdict]
            self.request.sendall(reply)
        except (OSError,KeyError):return


def run_cli(*args,env=None):
    return subprocess.run([sys.executable,'-B',str(ROOT/'tools/run_candidate.py'),*args],cwd=ROOT,
                          env=env,capture_output=True,text=True,timeout=25)


@contextmanager
def serving(data,port,logfile):
    import httpx
    kwargs={'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP} if os.name=='nt' else {'start_new_session':True}
    with logfile.open('wb') as log:
        process=subprocess.Popen([sys.executable,'-B',str(ROOT/'tools/run_candidate.py'),'serve','--data-dir',str(data),
                                  '--port',str(port),'--workers','2'],cwd=ROOT,stdout=log,stderr=log,**kwargs)
        try:
            deadline=time.monotonic()+25
            base=f'http://127.0.0.1:{port}'
            while time.monotonic()<deadline:
                if process.poll() is not None:
                    print(logfile.read_text(errors='replace')[-3500:])
                    raise AssertionError('normal candidate launcher exited')
                try:
                    with httpx.Client(trust_env=False,timeout=1) as client:r=client.get(base+'/healthz')
                    pids=set(re.findall(r'Started server process \[(\d+)\]',logfile.read_text(errors='replace')))
                    if r.status_code==200 and len(pids)==2:break
                except httpx.HTTPError:pass
                time.sleep(0.05)
            else:raise AssertionError('normal candidate did not start both workers')
            yield base
        finally:
            if process.poll() is None:
                process.send_signal(signal.CTRL_BREAK_EVENT if os.name=='nt' else signal.SIGTERM)
                try:process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    if os.name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=5)
                    else:os.killpg(process.pid,signal.SIGKILL)
                    process.wait(timeout=5)


class Fields(HTMLParser):
    def __init__(self):super().__init__();self.csrf=None
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='input' and attrs.get('name')=='csrf':self.csrf=attrs.get('value')


def main():
    import httpx
    from reportlab.pdfgen import canvas
    checks=0
    def check(ok,label):
        nonlocal checks
        assert ok,label
        checks+=1
        print('PASS: '+label,flush=True)
    with tempfile.TemporaryDirectory(prefix='FT10_SYNTHETIC_WORKFLOW_') as temp:
        root=Path(temp);data=root/'candidate'
        with FakeClamd(('127.0.0.1',0),ScannerHandler) as scanner:
            thread=threading.Thread(target=scanner.serve_forever,daemon=True);thread.start()
            try:
                result=run_cli('init','--data-dir',str(data),'--scanner-port',str(scanner.server_address[1]),'--confirm-synthetic-only')
                if result.returncode:print(result.stdout,result.stderr)
                check(result.returncode==0,'shipping init command creates a fresh candidate store')
                credentials=json.loads((data/'synthetic-accounts.json').read_text())['accounts']
                check(all(account['password'] not in result.stdout+result.stderr for account in credentials),'init never prints generated synthetic passwords')
                dbpath=data/'candidate.sqlite3'
                def rows(sql,values=()):
                    with sqlite3.connect(dbpath) as db:return db.execute(sql,values).fetchall()
                initial=rows('SELECT COUNT(*) FROM users')[0][0]
                check(run_cli('init','--data-dir',str(data),'--confirm-synthetic-only').returncode!=0
                      and rows('SELECT COUNT(*) FROM users')[0][0]==initial,'re-initialization refuses existing data without overwrite/reseed')
                production=os.environ.copy();production['PORTAL_ENV']='production'
                check(run_cli('init','--data-dir',str(root/'forbidden'),'--confirm-synthetic-only',env=production).returncode!=0
                      and not (root/'forbidden').exists(),'production-mode initialization refuses before any data write')
                check(run_cli('check','--data-dir',str(data)).returncode==0,'shipping check validates versioned candidate schema')
                config=(data/'candidate.json').read_text()
                altered=json.loads(config);altered['release_gate']='GO'
                (data/'candidate.json').write_text(json.dumps(altered))
                check(run_cli('check','--data-dir',str(data)).returncode!=0,'modified release gate cannot activate candidate')
                (data/'candidate.json').write_text(config)
                with sqlite3.connect(dbpath) as db:
                    db.execute('PRAGMA foreign_keys=ON')
                    try:
                        db.execute("INSERT INTO candidate_pdf_av_attestations (report_id,schema_version,sha256,verdict,source,scanned_at_utc) VALUES (999,1,?,'clean','clamd-instream-v1','2026-10-28T00:00:00+00:00')",('0'*64,))
                    except sqlite3.IntegrityError:check(True,'candidate AV schema rejects orphan report attestations')
                    else:raise AssertionError('missing AV foreign key')
                    db.rollback()
                legacy_env=os.environ.copy()
                legacy_env.update(PORTAL_ENV='development',DATABASE_URL='sqlite:///'+dbpath.as_posix(),
                                  PRIVATE_STORAGE=str(root/'wrong-storage'))
                legacy_env.pop('PORTAL_CANDIDATE_INSTANCE',None)
                bypass=subprocess.run([sys.executable,'-B','-c','import runpy;runpy.run_path(__import__("sys").argv[1])',str(ROOT/'app/portal.py')],
                                      env=legacy_env,cwd=ROOT,capture_output=True,text=True,timeout=15)
                check(bypass.returncode!=0 and 'managed candidate requires' in bypass.stderr
                      and not (root/'wrong-storage').exists(),'legacy entrypoint cannot silently bypass candidate policy or modify its store')
                slot=data/'shared-admission/total/slot-1'
                slot.rename(slot.with_name('saved-slot'))
                check(run_cli('check','--data-dir',str(data)).returncode!=0 and not slot.exists(),
                      'normal startup refuses missing shared state without replacing active lock files')
                slot.with_name('saved-slot').rename(slot)
                with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                clients={role:httpx.Client(base_url=f'http://127.0.0.1:{port}',trust_env=False,timeout=10,follow_redirects=False)
                         for role in ('staff','patient','other')}
                legacyid,patientid=rows('SELECT id,patient_id FROM reports')[0]
                payload=io.BytesIO();pdf=canvas.Canvas(payload);pdf.drawString(60,700,'SYNTHETIC NORMAL CANDIDATE UPLOAD');pdf.save()
                pdfbytes=payload.getvalue()
                try:
                    with serving(data,port,root/'first-server.log'):
                        for role,account in zip(('staff','patient','other'),credentials):
                            client=clients[role]
                            login=client.get('/login')
                            check(login.status_code==200 and 'HOLD / NO-GO' in login.text and 'ТЕСТОВ КАНДИДАТ' in login.text,'normal '+role+' login shows Bulgarian candidate boundary')
                            token=client.cookies.get('login_csrf')
                            r=client.post('/login',data={'username':account['username'],'password':account['password'],'login_token':token})
                            check(r.status_code==303,'normal synthetic '+role+' authentication succeeds')
                        staff=clients['staff'];patient=clients['patient'];other=clients['other']
                        detail=staff.get(f'/patients/{patientid}')
                        fields=Fields();fields.feed(detail.text);csrf=fields.csrf
                        check(detail.status_code==200 and csrf and 'Провери с антивирус' in detail.text,'normal staff UI automatically includes protected rescan path')
                        check(patient.get(f'/reports/{legacyid}/download').status_code==423,'normal startup holds legacy PDF without an AV attestation')
                        check(other.get(f'/reports/{legacyid}/download').status_code==404,'cross-patient legacy access remains denied')
                        check(patient.post(f'/reports/{legacyid}/scan',data={'csrf':csrf}).status_code==403,'patient cannot attest a legacy report')
                        check(staff.post(f'/reports/{legacyid}/scan',data={'csrf':'invalid'}).status_code==403,'normal scan route enforces CSRF')
                        form={'csrf':csrf,'title':'Синтетичен нов документ','modality':'ЯМР','exam_date':'2020-01-01','confirm_owner':'yes'}
                        scanner.verdict='error'
                        before=rows('SELECT COUNT(*) FROM reports')[0][0]
                        r=staff.post(f'/patients/{patientid}/reports',data=form,files={'file':('synthetic.pdf',pdfbytes,'application/pdf')})
                        check(r.status_code==503 and rows('SELECT COUNT(*) FROM reports')[0][0]==before,'normal upload refuses scanner error with no report row')
                        scanner.verdict='found'
                        r=staff.post(f'/patients/{patientid}/reports',data=form,files={'file':('synthetic.pdf',pdfbytes,'application/pdf')})
                        check(r.status_code==422 and 'Synthetic-Only' not in r.text,'scanner FOUND refuses upload without exposing its signature')
                        scanner.verdict='clean'
                        r=staff.post(f'/patients/{patientid}/reports',data=form,files={'file':('synthetic.pdf',pdfbytes,'application/pdf')})
                        check(r.status_code==303,'normal INSTREAM clean response creates a draft without worker monkeypatches')
                        docid,checksum,published=rows('SELECT id,file_sha256,published_at FROM reports ORDER BY id DESC LIMIT 1')[0]
                        check(checksum==hashlib.sha256(pdfbytes).hexdigest() and published is None,'normal uploaded draft records exact checksum and stays unpublished')
                        check(rows('SELECT verdict,source FROM candidate_pdf_av_attestations WHERE report_id=?',(docid,))==[('clean','clamd-instream-v1')],'draft transaction also persists durable AV evidence')
                        check(patient.get(f'/reports/{docid}/download').status_code==404,'patient cannot download draft')
                        check(staff.post(f'/reports/{docid}/publish',data=form).status_code==422,'normal publish still requires preview')
                        check(staff.get(f'/reports/{docid}/preview').content==pdfbytes,'normal staff preview returns exact attested bytes')
                        check(staff.post(f'/reports/{docid}/publish',data={**form,'csrf':'bad'}).status_code==403,'normal publish preserves CSRF protection')
                        check(staff.post(f'/reports/{docid}/publish',data=form).status_code==303,'normal preview-confirm-publish workflow succeeds')
                        check(patient.get(f'/reports/{docid}/download').content==pdfbytes,'published document delivers exact bytes to owner')
                        check(other.get(f'/reports/{docid}/download').status_code==404,'published document remains unavailable to other patient')
                        scanner.verdict='error'
                        check(staff.post(f'/reports/{legacyid}/scan',data={'csrf':csrf}).status_code==503
                              and patient.get(f'/reports/{legacyid}/download').status_code==423,'failed legacy scan remains held')
                        scanner.verdict='clean'
                        check(staff.post(f'/reports/{legacyid}/scan',data={'csrf':csrf}).status_code==303,'explicit normal legacy rescan records clean result')
                        check(patient.get(f'/reports/{legacyid}/download').content==(data/'files/synthetic-legacy.pdf').read_bytes(),'legacy owner delivery recovers after clean rescan')
                        total=DiskSlotPool(data/'shared-admission/total',2)
                        a,b=total.try_acquire(),total.try_acquire()
                        try:
                            check(patient.get(f'/reports/{docid}/download').status_code==503,'normal startup automatically uses the global worker admission pool')
                            check(patient.get('/dashboard').status_code==200,'candidate dashboard remains available at full PDF capacity')
                        finally:a.close();b.close()
                        state=rows('SELECT COUNT(*) FROM users')[0]+rows('SELECT COUNT(*) FROM reports')[0]
                    # Use the same shipping serve command, same directory and
                    # cookies; no reinitialization, fixture installer or backfill.
                    with serving(data,port,root/'second-server.log'):
                        check(patient.get('/dashboard').status_code==200,'existing synthetic session survives normal server restart')
                        check(patient.get(f'/reports/{docid}/download').content==pdfbytes,'AV attestation and delivery survive restart')
                        check(state==rows('SELECT COUNT(*) FROM users')[0]+rows('SELECT COUNT(*) FROM reports')[0],'restart never reseeds or duplicates accounts/reports')
                        check(staff.get('/reports').status_code==200 and staff.get('/audit').status_code==200,'normal candidate retains staff report and audit pages')
                    check(scanner.scans>=5,'actual candidate INSTREAM client exercised local fake scanner protocol')
                finally:
                    for client in clients.values():client.close()
                report={'mode':'SHIPPING CLI / NORMAL CANDIDATE / SYNTHETIC ONLY','checks_passed':checks,
                        'workers':2,'restart_verified':True,'scanner':'fake loopback INSTREAM server; no real AV claim',
                        'release_gate':'HOLD / NO-GO','production_approved':False}
                (ROOT/'reports/last_candidate_workflow.json').write_text(json.dumps(report,indent=2))
            finally:scanner.shutdown();thread.join(timeout=3)
    print(f'PASS: FT10 NORMAL CANDIDATE WORKFLOW ({checks} checks). HOLD / NO-GO.')


if __name__=='__main__':main()
