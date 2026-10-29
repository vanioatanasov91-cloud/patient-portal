"""Fast Track 6: fake-only clamd INSTREAM protocol and upload failure isolation.

Uses monkeypatched localhost socket; no actual scanner/network service or real data.
"""
from __future__ import annotations

import gc
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))
from test_pdf_hardening import safe_copy


class FakeClamdSocket:
    def __init__(self, reply: bytes, mutate=None):
        self.reply = reply
        self.sent = bytearray()
        self.mutate = mutate
        self.received = False
        self.timeout = None

    def __enter__(self): return self
    def __exit__(self, *_): return False
    def settimeout(self, value): self.timeout = value
    def sendall(self, data):
        self.sent.extend(data)
        if self.mutate and data == b'\0\0\0\0':
            self.mutate()
    def recv(self, n):
        if self.received: return b''
        self.received = True
        return self.reply[:n]


def run():
    from fastapi import HTTPException
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas
    from sqlalchemy import select

    original_env = os.environ.copy()
    name = 'ft6_clamd_synthetic_candidate'
    app = None
    counter = 0

    def passed(ok, label):
        nonlocal counter
        if not ok: raise AssertionError(label)
        counter += 1
        print('PASS: ' + label, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix='FT6_SCAN_FAKE_ONLY_') as folder:
            root = Path(folder)
            appdir = root/'app'
            appdir.mkdir()
            safe_copy(appdir)
            uploads = root/'uploads'
            uploads.mkdir()
            dbfile = root/'fake.sqlite3'
            os.environ.update({
                'PORTAL_ENV':'development',
                'PORTAL_SECRET':secrets.token_urlsafe(48),
                'PORTAL_COOKIE_SECURE':'1',
                'PORTAL_ALLOWED_HOSTS':'portal.example.test',
                'DATABASE_URL':'sqlite:///'+dbfile.as_posix(),
                'PRIVATE_STORAGE':str(uploads),
                'PORTAL_PDF_SCAN_MODE':'off',
            })
            # Separate interpreter proves that deployment cannot accidentally
            # start with production mode while malware scanning is disabled.
            production_env = os.environ.copy()
            production_env['PORTAL_ENV'] = 'production'
            result = subprocess.run([
                sys.executable,'-B','-c',
                'import runpy,sys;runpy.run_path(sys.argv[1])',str(appdir/'portal.py'),
            ],cwd=str(root),env=production_env,capture_output=True,text=True,timeout=20)
            passed(result.returncode != 0 and 'production PDF upload requires clamd scanning' in result.stderr,
                   'production startup is blocked when scanner mode is off')

            spec = importlib.util.spec_from_file_location(name,appdir/'portal.py')
            assert spec and spec.loader
            app = importlib.util.module_from_spec(spec)
            sys.modules[name] = app
            spec.loader.exec_module(app)
            real_create = app.socket.create_connection
            try:
                passed(app.PDF_SCAN_MODE == 'off','development defaults to explicitly unscanned uploads')
                pdf = io.BytesIO()
                c=canvas.Canvas(pdf)
                c.drawString(70,725,'SYNTHETIC PDF FOR OFFLINE SCAN TEST')
                c.save()
                payload=pdf.getvalue()
                pdfpath = root/'fake_payload.pdf'
                pdfpath.write_bytes(payload)
                passed(app.scan_pdf_for_malware(pdfpath) is False,
                       'disabled scanner is never misrepresented as clean')

                app.PDF_SCAN_MODE='clamd'
                fake = FakeClamdSocket(b'stream: OK\0')
                connections=[]
                def connect(addr,timeout):
                    connections.append((addr,timeout))
                    return fake
                app.socket.create_connection=connect
                passed(app.scan_pdf_for_malware(pdfpath) is True,'explicit clamd OK is accepted')
                passed(connections == [(('127.0.0.1',3310),5.0)],
                       'only local clamd endpoint is contacted with short timeout')
                passed(fake.sent.startswith(b'zINSTREAM\0') and fake.sent.endswith(b'\0\0\0\0'),
                       'scan uses framed clamd INSTREAM protocol')
                passed(payload in fake.sent and fake.timeout == 5.0,
                       'scanner receives synthetic PDF bytes through bounded stream')

                def scan_reply(reply, exception=HTTPException):
                    app.socket.create_connection=lambda *args,**kw: FakeClamdSocket(reply)
                    try:
                        app.scan_pdf_for_malware(pdfpath)
                    except exception as exc:
                        return exc
                    raise AssertionError('scanner fail-closed expectation violated')

                infected=scan_reply(b'stream: Eicar-Test-Signature FOUND\0')
                passed(infected.status_code==422 and 'Eicar' not in str(infected.detail),
                       'malware FOUND verdict is rejected without exposing signature')
                for reply in (b'stream: ERROR\0', b'stream: INSTREAM size limit exceeded ERROR\0',b'malformed\0',b''):
                    err=scan_reply(reply)
                    passed(err.status_code==503,'scanner failed/invalid reply remains fail closed')
                def offline(*a,**k): raise ConnectionRefusedError('SYNTHETIC_CLAMD_DOWN')
                app.socket.create_connection=offline
                err=None
                try: app.scan_pdf_for_malware(pdfpath)
                except HTTPException as exc:err=exc
                passed(err is not None and err.status_code==503 and err.headers.get('Retry-After')=='30',
                       'scanner outage refuses uploads and advises retry')

                # Validate actual staff upload endpoint, not just the utility.
                pw=secrets.token_urlsafe(24)
                with app.SessionLocal() as db:
                    staff=app.User(username='FT6_FAKE_STAFF',full_name='SYNTHETIC',role='staff',
                                   active=True,password_hash=app.ph.hash(pw))
                    patient=app.User(username='FT6_FAKE_PATIENT',full_name='SYNTHETIC',role='patient',
                                     active=True,password_hash=app.ph.hash(secrets.token_urlsafe(24)))
                    db.add_all([staff,patient]);db.commit()
                    sid,pid=staff.id,patient.id
                with TestClient(app.app,base_url='https://portal.example.test',follow_redirects=False) as client:
                    csrf_cookie=client.get('/login').cookies.get('login_csrf')
                    login=client.post('/login',data={'username':'FT6_FAKE_STAFF','password':pw,
                                         'login_token':csrf_cookie},follow_redirects=False)
                    passed(login.status_code==303,'synthetic staff authenticated')
                    with app.SessionLocal() as db:
                        csrf=db.scalar(select(app.LoginSession).where(app.LoginSession.user_id==sid)).csrf_token

                    def upload(data):
                        return client.post(f'/patients/{pid}/reports',
                            files={'file':('synthetic.pdf',data,'application/pdf')},
                            data={'title':'SYNTHETIC SCANNED PDF','modality':'ЯМР','exam_date':'2020-01-01',
                                  'confirm_owner':'yes','csrf':csrf},follow_redirects=False)

                    app.socket.create_connection=lambda *a,**kw: FakeClamdSocket(b'stream: Eicar-Test-Signature FOUND\0')
                    bad=upload(payload)
                    passed(bad.status_code==422,'malware verdict blocks actual PDF upload route')
                    passed(not list(uploads.glob('*.pdf')),'malware rejected upload leaves no stored PDF')
                    with app.SessionLocal() as db:
                        passed(not db.scalars(select(app.Report)).all(),'malware verdict leaves no report row')

                    app.socket.create_connection=offline
                    down=upload(payload)
                    passed(down.status_code==503,'scanner outage blocks actual PDF upload route')
                    passed(not list(uploads.glob('*.pdf')),'outage leaves no stored PDF')

                    def change_on_close():
                        for item in uploads.glob('*.pdf'):
                            item.write_bytes(b'SYNTHETIC_TAMPER_AFTER_SCAN')
                    app.socket.create_connection=lambda *a,**kw: FakeClamdSocket(b'stream: OK\0',change_on_close)
                    tamper=upload(payload)
                    passed(tamper.status_code==409,'postscan PDF mutation is rejected before DB insert')
                    passed(not list(uploads.glob('*.pdf')),'postscan mutation leaves no stored PDF')

                    app.socket.create_connection=lambda *a,**kw: FakeClamdSocket(b'stream: OK\0')
                    good=upload(payload)
                    passed(good.status_code==303,'clean local scanner response permits synthetic draft')
                    with app.SessionLocal() as db:
                        rows=db.scalars(select(app.Report)).all()
                        passed(len(rows)==1 and rows[0].published_at is None,
                               'clean scanned document remains unpublished draft')
                        passed(rows[0].file_sha256==hashlib.sha256(payload).hexdigest(),
                               'accepted draft persists original SHA-256 checksum')
                    passed(len(list(uploads.glob('*.pdf')))==1,
                           'only scanned synthetic PDF is persisted')
            finally:
                app.socket.create_connection=real_create
                app.engine.dispose()
                sys.modules.pop(name,None)
                app=None
                gc.collect()
        print(f'PASS: FAST TRACK 6 PDF SCAN GATE COMPLETE ({counter} checks)')
        print('RELEASE GATE: HOLD / NO-GO. FAKE CLAMD ONLY; NO REAL MALWARE SCAN.')
    finally:
        os.environ.clear();os.environ.update(original_env)


if __name__=='__main__':
    try:run()
    except Exception as exc:
        print('FAIL/HOLD: FT6 fake-only scan test: '+type(exc).__name__+' (details withheld)',file=sys.stderr)
        print('RELEASE GATE: HOLD / NO-GO.',file=sys.stderr)
        sys.exit(1)
