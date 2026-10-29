"""Offline fake-only PDF workflow regression against the ACTUAL Fast Track 3 candidate.

Never accesses a real patient PDF, deployed service, or real database. It imports a
whitelisted candidate copy in a brand-new temporary directory with synthetic env.
"""
from __future__ import annotations

from contextlib import closing
from datetime import date
import gc
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / 'app'
ASSETS = {
    'templates': ('audit.html','base.html','change_password.html','credentials.html',
                  'detail.html','edit_patient.html','error.html','login.html','new_patient.html',
                  'patient.html','reports.html','settings.html','staff.html'),
    'static': ('style.css','portal-ui.js'),
}
count = 0


def passed(condition: bool, description: str):
    global count
    if not condition:
        raise AssertionError(description)
    count += 1
    print('PASS: ' + description, flush=True)


def safe_copy(to: Path):
    assert not SRC.is_symlink() and not (SRC / '.env').exists() and not (SRC / 'private_data').exists()
    for x in ['portal.py']:
        original = SRC / x
        assert original.is_file() and not original.is_symlink()
        shutil.copyfile(original, to / x)
    for folder, filenames in ASSETS.items():
        (to / folder).mkdir()
        for filename in filenames:
            original = SRC / folder / filename
            assert original.is_file() and not original.is_symlink() and original.stat().st_size < 1024*1024
            shutil.copyfile(original, to / folder / filename)


def run():
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas
    from sqlalchemy import select

    original_env = os.environ.copy()
    name = 'fasttrack3_pdf_fake_only'
    portal = None
    print('=== FAST TRACK 3 / PDF HARDENING (FAKE-ONLY) ===', flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix='FT3_PDF_FAKE_') as temp:
            root = Path(temp)
            appdir = root/'app'
            appdir.mkdir()
            safe_copy(appdir)
            uploads = root/'upload_fake'
            uploads.mkdir()
            db_path = root/'synthetic.sqlite3'
            os.environ.update({
                'PORTAL_ENV': 'development',
                'PORTAL_SECRET': secrets.token_urlsafe(48),
                'PORTAL_COOKIE_SECURE': '1',
                'PORTAL_ALLOWED_HOSTS': 'portal.example.test',
                'DATABASE_URL': 'sqlite:///' + db_path.as_posix(),
                'PRIVATE_STORAGE': str(uploads),
            })
            spec = importlib.util.spec_from_file_location(name, appdir/'portal.py')
            assert spec and spec.loader
            portal = importlib.util.module_from_spec(spec)
            sys.modules[name] = portal
            spec.loader.exec_module(portal)
            try:
                staff_pw = secrets.token_urlsafe(25)
                patient_pw = secrets.token_urlsafe(25)
                with portal.SessionLocal() as db:
                    staff = portal.User(username='FT3_FAKE_STAFF',full_name='FAKE STAFF',role='staff',
                                        active=True,password_hash=portal.ph.hash(staff_pw))
                    patient = portal.User(username='FT3_FAKE_PATIENT',full_name='FAKE PATIENT',role='patient',
                                          active=True,password_hash=portal.ph.hash(patient_pw))
                    db.add_all([staff,patient]); db.commit()
                    sid,pid = staff.id,patient.id

                pdf = io.BytesIO()
                c=canvas.Canvas(pdf)
                c.drawString(60,760,'SYNTHETIC PDF FOR FAST TRACK 3')
                c.save()
                pdf_bytes = pdf.getvalue()
                passed(pdf_bytes.startswith(b'%PDF-') and b'startxref' in pdf_bytes and b'%%EOF' in pdf_bytes,
                       'fixture is complete synthetic PDF')

                def upload(client, data, filename='synthetic.pdf'):
                    return client.post(f'/patients/{pid}/reports',
                                       files={'file':(filename,data,'application/pdf')},
                                       data={'title':'FAKE PDF','modality':'ЯМР',
                                             'exam_date':'2020-01-01','confirm_owner':'yes','csrf':csrf},
                                       follow_redirects=False)

                with TestClient(portal.app, base_url='https://portal.example.test', follow_redirects=False) as client:
                    page = client.get('/login')
                    passed(page.status_code==200,'fake login form accessible')
                    token = client.cookies.get('login_csrf')
                    response = client.post('/login',data={'username':'FT3_FAKE_STAFF',
                        'password':staff_pw,'login_token':token},follow_redirects=False)
                    passed(response.status_code==303,'fake staff authentication')
                    with portal.SessionLocal() as db:
                        session = db.scalar(select(portal.LoginSession).where(portal.LoginSession.user_id==sid))
                        csrf = session.csrf_token

                    response = upload(client, b'%PDF-1.4\nhello fake content\n%%EOF')
                    passed(response.status_code==422,'rejects header-only fake PDF without xref')
                    response = upload(client, pdf_bytes+b'APPENDED GARBAGE')
                    passed(response.status_code==422,'rejects trailing non-whitespace bytes')
                    response = upload(client, b'%PDF-1.7\n'+b'x'*(portal.MAX_PDF))
                    passed(response.status_code==413,'rejects PDF bigger than 15 MiB')
                    passed(not list(uploads.glob('*.pdf')),'rejected uploads leave no stored PDF')

                    response = upload(client, pdf_bytes)
                    passed(response.status_code==303,'complete synthetic PDF saved as draft')
                    with portal.SessionLocal() as db:
                        records=db.scalars(select(portal.Report)).all()
                        passed(len(records)==1 and records[0].published_at is None,
                               'accepted PDF remains unpublished draft')
                        docid=records[0].id
                        original_filename=records[0].stored_name
                        passed(records[0].file_sha256==hashlib.sha256(pdf_bytes).hexdigest(),
                               'accepted draft stores SHA256 fingerprint')
                    storage_file = uploads/original_filename
                    passed(storage_file.read_bytes()==pdf_bytes,'stored bytes match submitted PDF')
                    response=upload(client,pdf_bytes)
                    passed(response.status_code==409,'identical duplicate draft rejected')
                    passed(len(list(uploads.glob('*.pdf')))==1,'duplicate upload leaves no orphan file')

                    response=client.post(f'/reports/{docid}/publish',
                                         data={'csrf':csrf,'confirm_owner':'yes'},follow_redirects=False)
                    passed(response.status_code==422,'publish requires staff PDF preview')
                    response=client.get(f'/reports/{docid}/preview')
                    passed(response.status_code==200 and response.content==pdf_bytes,'staff preview returns verified PDF')
                    with portal.SessionLocal() as db:
                        audit=db.scalar(select(portal.Audit).where(portal.Audit.action=='report_previewed'))
                        passed(audit is not None and audit.details=='sha256:'+hashlib.sha256(pdf_bytes).hexdigest(),
                               'preview audit binds exact PDF digest')

                    storage_file.write_bytes(pdf_bytes+b'TAMPER')
                    passed(client.get(f'/reports/{docid}/preview').status_code==409,
                           'corrupted draft preview blocked')
                    passed(client.post(f'/reports/{docid}/publish',
                                       data={'csrf':csrf,'confirm_owner':'yes'},follow_redirects=False).status_code==409,
                           'tampered draft cannot be published')
                    with portal.SessionLocal() as db:
                        passed(db.get(portal.Report,docid).published_at is None,
                               'tampered draft still unpublished')
                    storage_file.write_bytes(pdf_bytes)
                    response=client.post(f'/reports/{docid}/publish',
                                         data={'csrf':csrf,'confirm_owner':'yes'},follow_redirects=False)
                    passed(response.status_code==303,'restored and previewed PDF can be published')
                    with portal.SessionLocal() as db:
                        passed(db.get(portal.Report,docid).published_at is not None,
                               'published timestamp recorded')
                    passed(client.get(f'/reports/{docid}/download').status_code==200,
                           'verified published PDF available to authorized staff')
                    storage_file.write_bytes(pdf_bytes+b'TAMPER2')
                    passed(client.get(f'/reports/{docid}/download').status_code==409,
                           'corrupted published PDF download blocked')
                    passed(client.get(f'/reports/{docid}/view').status_code==409,
                           'corrupted published PDF inline view blocked')
                    storage_file.write_bytes(pdf_bytes)
                    with portal.SessionLocal() as db:
                        doc=db.get(portal.Report,docid)
                        doc.stored_name='../../outside.pdf'
                        db.commit()
                    passed(client.get(f'/reports/{docid}/download').status_code==404,
                           'invalid DB stored path rejected')
                    with portal.SessionLocal() as db:
                        doc=db.get(portal.Report,docid)
                        doc.stored_name=original_filename
                        db.commit()
                    passed(client.get(f'/reports/{docid}/download').status_code==200,
                           'restored stored path still works')
                    with closing(sqlite3.connect(str(db_path))) as db:
                        passed(db.execute('PRAGMA integrity_check').fetchone()[0]=='ok',
                               'synthetic SQLite integrity OK')
            finally:
                portal.engine.dispose()
                sys.modules.pop(name,None)
                portal = None
                gc.collect()
        print(f'PASS: FAST TRACK 3 PDF SECURITY COMPLETE ({count} checks)')
        print('RELEASE GATE: HOLD / NO-GO. NOT A MALWARE/ACTIVE-CONTENT SCAN.')
    finally:
        os.environ.clear(); os.environ.update(original_env)


if __name__ == '__main__':
    try:
        run()
    except Exception as e:
        print('FAIL/HOLD: Fast Track 3 PDF test: '+type(e).__name__+' (details withheld)',file=sys.stderr)
        print('RELEASE GATE: HOLD / NO-GO.',file=sys.stderr)
        sys.exit(1)
