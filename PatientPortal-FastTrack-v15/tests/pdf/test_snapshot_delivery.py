"""FastTrack4: test that the HTTP body equals the bytes that passed SHA-256.

Offline, synthetic-only. Does not access deployed services, patient files or real DB.
"""
from __future__ import annotations
import gc
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import secrets
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))
from test_pdf_hardening import safe_copy


def run():
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas
    from sqlalchemy import select
    initial_env=os.environ.copy()
    count=0
    name='fasttrack4_snapshot_fake_only'
    portal=None
    def ok(check,label):
        nonlocal count
        if not check:
            raise AssertionError(label)
        count+=1
        print('PASS: '+label,flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix='FT4_SNAPSHOT_FAKE_') as scratch:
            root=Path(scratch)
            folder=root/'app';folder.mkdir()
            safe_copy(folder)
            storage=root/'fake_pdfs';storage.mkdir()
            dbfile=root/'fake.sqlite3'
            os.environ.update({
                'PORTAL_ENV':'development',
                'PORTAL_SECRET':secrets.token_urlsafe(48),
                'PORTAL_COOKIE_SECURE':'1',
                'PORTAL_ALLOWED_HOSTS':'portal.example.test',
                'DATABASE_URL':'sqlite:///'+dbfile.as_posix(),
                'PRIVATE_STORAGE':str(storage),
            })
            spec=importlib.util.spec_from_file_location(name,folder/'portal.py')
            assert spec and spec.loader
            portal=importlib.util.module_from_spec(spec)
            sys.modules[name]=portal
            spec.loader.exec_module(portal)
            try:
                staff_pass=secrets.token_urlsafe(24)
                with portal.SessionLocal() as db:
                    staff=portal.User(username='FT4_FAKE_ADMIN',full_name='FAKE ADMIN',role='staff',
                                      active=True,password_hash=portal.ph.hash(staff_pass))
                    patient=portal.User(username='FT4_FAKE_PATIENT',full_name='FAKE PATIENT',role='patient',
                                       active=True,password_hash=portal.ph.hash(secrets.token_urlsafe(24)))
                    db.add_all([staff,patient]); db.commit()
                    sid,pid=staff.id,patient.id
                buf=io.BytesIO()
                pdf=canvas.Canvas(buf)
                pdf.drawString(52,744,'SYNTHETIC SNAPSHOT REGRESSION')
                pdf.save()
                payload=buf.getvalue()
                with TestClient(portal.app,base_url='https://portal.example.test',follow_redirects=False) as client:
                    token=client.get('/login').cookies.get('login_csrf')
                    login=client.post('/login',data={'username':'FT4_FAKE_ADMIN','password':staff_pass,
                                                     'login_token':token}, follow_redirects=False)
                    ok(login.status_code==303,'synthetic staff login successful')
                    with portal.SessionLocal() as db:
                        csrf=db.scalar(select(portal.LoginSession).where(portal.LoginSession.user_id==sid)).csrf_token
                    response=client.post(f'/patients/{pid}/reports',
                        files={'file':('synthetic.pdf',payload,'application/pdf')},
                        data={'title':'FAKE RESULT','modality':'ЯМР','exam_date':'2020-01-01',
                              'confirm_owner':'yes','csrf':csrf},follow_redirects=False)
                    ok(response.status_code==303,'synthetic PDF created as draft')
                    with portal.SessionLocal() as db:
                        doc=db.scalar(select(portal.Report).where(portal.Report.patient_id==pid))
                        docid=doc.id
                        pdf_path=storage/doc.stored_name
                    good=portal.snapshot_verified_pdf
                    digest=hashlib.sha256(payload).hexdigest()
                    def replace_after_snapshot(doc):
                        data,sha=good(doc)
                        # Models a writer changing the on-disk file after hashing but
                        # BEFORE the HTTP response object is constructed / streamed.
                        pdf_path.write_bytes(b'FAKE TAMPER AFTER CHECK')
                        return data,sha
                    portal.snapshot_verified_pdf=replace_after_snapshot
                    try:
                        preview=client.get(f'/reports/{docid}/preview')
                    finally:
                        portal.snapshot_verified_pdf=good
                    ok(preview.status_code==200 and preview.content==payload,
                       'preview serves immutable verified bytes despite later file mutation')
                    ok('inline' in preview.headers.get('content-disposition','').lower(),
                       'preview uses inline disposition')
                    ok(preview.headers.get('x-content-type-options')=='nosniff' and
                       'no-store' in preview.headers.get('cache-control',''),
                       'preview response includes no-store and nosniff')
                    ok(pdf_path.read_bytes()!=payload,'synthetic mutation occurred after snapshot')
                    rejected=client.get(f'/reports/{docid}/preview')
                    ok(rejected.status_code==409,'pre-snapshot tampered PDF rejected')
                    pdf_path.write_bytes(payload)
                    published=client.post(f'/reports/{docid}/publish',
                        data={'csrf':csrf,'confirm_owner':'yes'},follow_redirects=False)
                    ok(published.status_code==303,'original previewed bytes can be published')
                    for endpoint in ('view','download'):
                        portal.snapshot_verified_pdf=replace_after_snapshot
                        try:
                            response=client.get(f'/reports/{docid}/{endpoint}')
                        finally:
                            portal.snapshot_verified_pdf=good
                        ok(response.status_code==200 and response.content==payload,
                           endpoint+' serves original verified bytes after mutation')
                        expected='inline' if endpoint=='view' else 'attachment'
                        ok(response.headers.get('content-disposition','').startswith(expected),
                           endpoint+' has correct disposition')
                        ok(response.headers.get('x-content-type-options')=='nosniff' and
                           'no-store' in response.headers.get('cache-control',''),
                           endpoint+' has protective response headers')
                        pdf_path.write_bytes(payload)
                    original_limit=portal.MAX_SERVED_PDF
                    portal.MAX_SERVED_PDF=len(payload)-1
                    try:
                        oversized=client.get(f'/reports/{docid}/download')
                    finally:
                        portal.MAX_SERVED_PDF=original_limit
                    ok(oversized.status_code==409,'stored snapshot size limit enforced')
                    ok(pdf_path.read_bytes()==payload,'test restores fake storage bytes')
            finally:
                portal.engine.dispose()
                sys.modules.pop(name,None)
                portal=None
                gc.collect()
        print(f'PASS: FAST TRACK 4 PDF SNAPSHOT COMPLETE ({count} checks)')
        print('RELEASE GATE: HOLD / NO-GO. NOT PRODUCTION APPROVED.')
    finally:
        os.environ.clear();os.environ.update(initial_env)


if __name__=='__main__':
    try:
        run()
    except Exception as exc:
        print('FAIL/HOLD: Fast Track 4 synthetic snapshot test: '+type(exc).__name__+' (details withheld)',file=sys.stderr)
        print('RELEASE GATE: HOLD / NO-GO.',file=sys.stderr)
        sys.exit(1)
