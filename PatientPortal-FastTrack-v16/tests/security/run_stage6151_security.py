"""Stage 6.15.1 offline security regression against current candidate app/portal.py.
No real localhost HTTP, Windows service, patient data, real backups, or real secrets.
Runs in-process HTTPS TestClient against newly generated synthetic SQLite and PDF.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import date, timedelta
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

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parents[1] / 'app'
MANIFEST = ROOT.parents[1] / 'MANIFEST_SHA256.json'
PINNED_PORTAL_SHA256 = __import__('json').loads(MANIFEST.read_text(encoding='utf-8'))['app/portal.py']
UI_FILES = {
    'templates': ('audit.html','base.html','change_password.html','credentials.html','detail.html','edit_patient.html','error.html','login.html','new_patient.html','patient.html','reports.html','settings.html','staff.html'),
    'static': ('portal-ui.js','style.css'),
}

class TestFailure(AssertionError):
    pass

checks = 0

def require(condition: bool, label: str) -> None:
    global checks
    if not condition:
        raise TestFailure(label)
    checks += 1
    print('PASS: ' + label, flush=True)


def safe_source_copy(destination: Path) -> None:
    src = SOURCE / 'portal.py'
    require(src.is_file() and not src.is_symlink() and hashlib.sha256(src.read_bytes()).hexdigest() == PINNED_PORTAL_SHA256,
            'v1.7 source SHA-256 matches bundled candidate integrity manifest')
    require(not (SOURCE/'.env').exists() and not (SOURCE/'private_data').exists(),
            'fixture includes no .env or private_data')
    shutil.copyfile(src, destination/'portal.py')
    for dirname, names in UI_FILES.items():
        root = SOURCE/dirname
        require(root.is_dir() and not root.is_symlink(), dirname+' source directory is present')
        (destination/dirname).mkdir()
        for filename in names:
            f = root/filename
            if not f.is_file() or f.is_symlink() or f.stat().st_size >= 2*1024*1024:
                raise TestFailure('unsafe or missing fixture asset')
            shutil.copyfile(f, destination/dirname/filename)
    require(True, 'only whitelisted UI assets copied into temporary isolated app')



@contextmanager
def temporary_workspace_with_db_cleanup(get_portal):
    # On Windows, SQLite must be disconnected BEFORE TemporaryDirectory cleanup.
    # Context exit order matters: engine.dispose() inside this block, not in
    # the enclosing main() finally (which runs after the temp folder is removed).
    with tempfile.TemporaryDirectory(prefix='stage6151_FAKE_ONLY_') as tmp:
        try:
            yield tmp
        finally:
            active_portal = get_portal()
            if active_portal is not None and hasattr(active_portal, 'engine'):
                active_portal.engine.dispose()
            gc.collect()


def main() -> None:
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas
    from sqlalchemy import select, func

    print('=== STAGE 6.15.1 | OFFLINE SYNTHETIC SECURITY TEST ===')
    print('INFO: Only pinned fixture; temporary FAKE data; in-process TestClient; no network listener.')
    print('INFO: Production policy simulated in-memory, NOT a test of real production configuration.')
    old_env = os.environ.copy()
    module_name = 'stage6151_fake_portal'
    portal = None
    try:
        with temporary_workspace_with_db_cleanup(lambda: portal) as tmp:
            home = Path(tmp)
            appdir = home/'fake_app'
            appdir.mkdir()
            safe_source_copy(appdir)
            dbfile = home/'fake.sqlite3'
            upload_dir = home/'fake_uploads'
            upload_dir.mkdir()
            # Preserve operator's environment; override all settings needed by fixture.
            # Never load the real .env or use the real DATABASE_URL/PRIVATE_STORAGE.
            os.environ.update({
                'PORTAL_ENV': 'production',
                'PORTAL_PDF_SCAN_MODE': 'clamd',  # only synthetic policy; no scanner/network used
                'PORTAL_SECRET': secrets.token_urlsafe(52),
                'PORTAL_COOKIE_SECURE': '1',
                'PORTAL_ALLOWED_HOSTS': 'portal.example.test',
                'DATABASE_URL': 'sqlite:///' + dbfile.as_posix(),
                'PRIVATE_STORAGE': str(upload_dir),
            })
            spec = importlib.util.spec_from_file_location(module_name, appdir/'portal.py')
            if spec is None or spec.loader is None:
                raise TestFailure('fixture module cannot be loaded')
            portal = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = portal
            spec.loader.exec_module(portal)
            require(portal.PROD and portal.COOKIE_SECURE, 'synthetic production policy enables secure cookies')

            staff_pw=secrets.token_urlsafe(21)
            patient_pw=secrets.token_urlsafe(21)
            other_pw=secrets.token_urlsafe(21)
            no_mfa_pw=secrets.token_urlsafe(21)
            synthetic_totp_secret='JBSWY3DPEHPK3PXP'   # intentionally fake test vector
            pdf_stream=io.BytesIO()
            c=canvas.Canvas(pdf_stream)
            c.drawString(60,760,'FAKE TEST PATIENT -- NEVER USE REAL HEALTH DATA')
            c.save()
            pdf_bytes=pdf_stream.getvalue()
            stored='fake_6151_document.pdf'
            (upload_dir/stored).write_bytes(pdf_bytes)
            for additional in ('fake_6151_draft.pdf','fake_6151_revoked.pdf'):
                (upload_dir/additional).write_bytes(pdf_bytes)
            with portal.SessionLocal() as s:
                staff=portal.User(username='FAKE_STAGE6151_STAFF', full_name='FAKE STAFF', role='staff',active=True,
                                  password_hash=portal.ph.hash(staff_pw),mfa_secret_enc=portal.encrypt_mfa_secret(synthetic_totp_secret))
                staff_unenrolled=portal.User(username='FAKE_STAGE6151_NO_MFA',full_name='FAKE STAFF NO MFA',role='staff',active=True,
                                             password_hash=portal.ph.hash(no_mfa_pw))
                owner=portal.User(username='FAKE_STAGE6151_OWNER',full_name='FAKE OWNER',role='patient',active=True,
                                  password_hash=portal.ph.hash(patient_pw))
                other=portal.User(username='FAKE_STAGE6151_OTHER',full_name='FAKE OTHER',role='patient',active=True,
                                  password_hash=portal.ph.hash(other_pw))
                s.add_all([staff,staff_unenrolled,owner,other]); s.commit()
                owner_id, other_id, staff_id=owner.id,other.id,staff.id
                document=portal.Report(patient_id=owner.id,uploaded_by=staff.id,modality='ЯМР',title='FAKE TEST REPORT',
                                       exam_date=date(2026,10,28),stored_name=stored,original_name='fake.pdf',
                                       published_at=portal.now(),file_sha256=hashlib.sha256(pdf_bytes).hexdigest())
                draft=portal.Report(patient_id=owner.id,uploaded_by=staff.id,modality='ЯМР',title='FAKE DRAFT',
                                    exam_date=date(2026,10,28),stored_name='fake_6151_draft.pdf',original_name='fake.pdf',published_at=None)
                revoked=portal.Report(patient_id=owner.id,uploaded_by=staff.id,modality='ЯМР',title='FAKE REVOKED',
                                      exam_date=date(2026,10,28),stored_name='fake_6151_revoked.pdf',original_name='fake.pdf',
                                      published_at=portal.now(),revoked_at=portal.now())
                s.add_all([document,draft,revoked]);s.commit()
                document_id,draft_id,revoked_id=document.id,draft.id,revoked.id

            base_url='https://portal.example.test'
            def auth(client, username, password, code=''):
                form=client.get('/login',follow_redirects=False)
                require(form.status_code == 200, 'login form reachable in isolated HTTPS client')
                csrf=client.cookies.get('login_csrf')
                require(bool(csrf),'login CSRF cookie issued')
                return client.post('/login',data={'username':username,'password':password,'login_token':csrf,'mfa_code':code},follow_redirects=False)

            with TestClient(portal.app,base_url=base_url,follow_redirects=False) as public:
                r=public.get('/login')
                require(r.status_code==200 and r.headers.get('x-frame-options')=='DENY' and
                        r.headers.get('x-content-type-options')=='nosniff' and
                        'frame-ancestors' in r.headers.get('content-security-policy',''),
                        'security headers (CSP, frame denial, nosniff) present')
                require('max-age=' in r.headers.get('strict-transport-security',''),
                        'HSTS enabled in synthetic production mode')
                require(public.get('/dashboard',follow_redirects=False).status_code==303,
                        'unauthenticated dashboard redirects to login')
                require(public.get(f'/reports/{document_id}/download',follow_redirects=False).status_code==303,
                        'unauthenticated PDF cannot be downloaded')
                csrf=public.cookies.get('login_csrf')
                r=public.post('/login',data={'username':'FAKE_STAGE6151_OWNER','password':patient_pw,'login_token':'invalid'},
                              follow_redirects=False)
                require(r.status_code==403,'login CSRF mismatch rejected')

            with TestClient(portal.app,base_url=base_url,follow_redirects=False) as staff_not_ready:
                r=auth(staff_not_ready,'FAKE_STAGE6151_NO_MFA',no_mfa_pw)
                require(r.status_code==401 and not staff_not_ready.cookies.get('portal_session'),
                        'staff lacking MFA enrollment denied in synthetic production mode')
            with TestClient(portal.app,base_url=base_url,follow_redirects=False) as staff_invalid_code:
                r=auth(staff_invalid_code,'FAKE_STAGE6151_STAFF',staff_pw,'00000x')
                require(r.status_code==401,'invalid staff MFA code denied')
            with TestClient(portal.app,base_url=base_url,follow_redirects=False) as staff_client:
                code=portal.totp_now(synthetic_totp_secret)
                r=auth(staff_client,'FAKE_STAGE6151_STAFF',staff_pw,code)
                require(r.status_code==303 and r.headers.get('location')=='/dashboard',
                        'enrolled staff with correct synthetic MFA authenticates')
                cookie_headers=r.headers.get('set-cookie','').lower()
                require('portal_session=' in cookie_headers and 'secure' in cookie_headers and
                        'httponly' in cookie_headers and 'samesite=lax' in cookie_headers,
                        'authenticated session cookie Secure, HttpOnly, SameSite=Lax')
                session_cookie=staff_client.cookies.get('portal_session')
                require(bool(session_cookie),'authenticated session exists')
                require(staff_client.get('/audit').status_code==200,'audit page visible only to staff')
                require(staff_client.get(f'/reports/{document_id}/preview').status_code==200,
                        'staff preview of synthetic PDF permitted')
                with portal.SessionLocal() as s:
                    ses=s.scalar(select(portal.LoginSession).where(portal.LoginSession.user_id==staff_id))
                    require(ses is not None and ses.mfa_verified,'server-side staff session records MFA verified')
                    staff_csrf=ses.csrf_token
                r=staff_client.post(f'/reports/{document_id}/revoke',data={'csrf':'not-a-real-token'},follow_redirects=False)
                require(r.status_code==403,'staff state-changing POST rejects invalid CSRF')
                with portal.SessionLocal() as s:
                    require(s.get(portal.Report,document_id).revoked_at is None,
                            'CSRF rejection leaves document unchanged')
                r=staff_client.post(f'/reports/{document_id}/revoke',data={'csrf':staff_csrf},follow_redirects=False)
                require(r.status_code==303,'staff authorized revoke succeeds on fake-only document')
                require(staff_client.get('/audit').status_code==200,'audit accessible after fake revoke')

            with TestClient(portal.app,base_url=base_url,follow_redirects=False) as owner_client:
                r=auth(owner_client,'FAKE_STAGE6151_OWNER',patient_pw)
                require(r.status_code==303,'synthetic patient login succeeds')
                require(owner_client.get('/dashboard').status_code==200,'owner sees own dashboard')
                require(owner_client.get('/reports').status_code==403 and owner_client.get('/settings').status_code==403 and
                        owner_client.get('/audit').status_code==403,
                        'patient blocked from staff registry, settings and audit')
                require(owner_client.get(f'/reports/{draft_id}/download').status_code==404,
                        'unpublished synthetic PDF inaccessible to its patient')
                require(owner_client.get(f'/reports/{revoked_id}/view').status_code==404,
                        'revoked PDF not viewable by its patient')
                require(owner_client.get(f'/reports/{document_id}/download').status_code==404,
                        'staff revocation invalidates patient download')
                with portal.SessionLocal() as s:
                    ses=s.scalar(select(portal.LoginSession).where(portal.LoginSession.user_id==owner_id))
                    require(ses is not None,'patient session stored server-side')
                    csrf=ses.csrf_token
                require(owner_client.post('/logout',data={'csrf':'invalid'},follow_redirects=False).status_code==403,
                        'logout rejects invalid CSRF')
                require(owner_client.post('/logout',data={'csrf':csrf},follow_redirects=False).status_code==303,
                        'logout with valid CSRF succeeds')
                require(owner_client.get('/dashboard',follow_redirects=False).status_code==303,
                        'logout invalidates old authenticated session')

            with TestClient(portal.app,base_url=base_url,follow_redirects=False) as other_client:
                r=auth(other_client,'FAKE_STAGE6151_OTHER',other_pw)
                require(r.status_code==303,'different synthetic patient login succeeds')
                require(other_client.get(f'/reports/{draft_id}/view').status_code==404 and
                        other_client.get(f'/reports/{revoked_id}/download').status_code==404,
                        'cross-patient access to unpublished/revoked reports denied')
                # Restore synthetic published fake report state after revoke to verify IDOR independently.
                with portal.SessionLocal() as s:
                    fake=s.get(portal.Report,document_id)
                    fake.revoked_at=None
                    s.commit()
                require(other_client.get(f'/reports/{document_id}/view').status_code==404 and
                        other_client.get(f'/reports/{document_id}/download').status_code==404,
                        'cross-patient IDOR denied for published synthetic PDF')
                require(other_client.get(f'/reports/{document_id}/preview').status_code==403,
                        'patient denied staff-only PDF preview')
                # Check idle expiry using fake timestamps; never wait/attack a real session.
                with portal.SessionLocal() as s:
                    ses=s.scalar(select(portal.LoginSession).where(portal.LoginSession.user_id==other_id))
                    ses.expires_at=portal.now()-timedelta(seconds=1)
                    s.commit()
                require(other_client.get('/dashboard',follow_redirects=False).status_code==303,
                        'expired idle session rejected')
                r=auth(other_client,'FAKE_STAGE6151_OTHER',other_pw)
                require(r.status_code==303,'new login after idle expiry works')
                with portal.SessionLocal() as s:
                    ses=s.scalar(select(portal.LoginSession).where(portal.LoginSession.user_id==other_id))
                    ses.created_at=portal.now()-timedelta(hours=9)
                    s.commit()
                require(other_client.get('/dashboard',follow_redirects=False).status_code==303,
                        'absolute session limit (8h) enforced')

            # Bounded throttling test: seed fake historical failures, not brute-force actual endpoint.
            with TestClient(portal.app,base_url=base_url,follow_redirects=False) as rate_client:
                username='FAKE_STAGE6151_RATE'
                import hmac as hmac_mod
                key=hmac_mod.new(portal.SECRET.encode(), f'testclient|{username.casefold()}'.encode(),hashlib.sha256).hexdigest()
                with portal.SessionLocal() as s:
                    for _ in range(8):
                        s.add(portal.AuthFailure(fingerprint=key,occurred_at=portal.now()))
                    s.commit()
                r=auth(rate_client,username,'fake-password')
                require(r.status_code==429,'8 seeded synthetic login failures trigger rate limit')

            with portal.SessionLocal() as s:
                actions=set(s.scalars(select(portal.Audit.action)).all())
                require({'login_success','login_failed','report_revoked','logout'}.issubset(actions),
                        'audit records authentication, revoke and logout events')
                rows=s.scalars(select(portal.Audit)).all()
                require(all(not any(value in (row.details or '') for value in [staff_pw,patient_pw,other_pw,no_mfa_pw]) for row in rows),
                        'audit details do not contain generated fake passwords')
                require(all(len(x.fingerprint)==64 and all(c in '0123456789abcdef' for c in x.fingerprint) for x in s.scalars(select(portal.AuthFailure)).all()),
                        'login failures stored as SHA-256 keyed fingerprints')
            with closing(sqlite3.connect(dbfile.as_posix())) as con:
                require(con.execute('PRAGMA integrity_check').fetchone()[0]=='ok',
                        'synthetic SQLite integrity check successful')
    # Publish final PASS only after temp SQLite and the workspace have closed.
        print(f'PASS: STAGE6.15.1 SYNTHETIC SECURITY TESTS COMPLETE ({checks} assertions)')
        print('PASS: Temporary SQLite workspace released and cleaned up.')
        print('RELEASE GATE: HOLD / NO-GO. Independent security review and production evidence remain required.')
    finally:
        sys.modules.pop(module_name,None)
        os.environ.clear()
        os.environ.update(old_env)
        del portal
        gc.collect()

if __name__=='__main__':
    try:
        main()
    except Exception as error:
        # This is intentionally terse to avoid secrets in traces and screen captures.
        print('FAIL: STAGE6.15.1 synthetic test: '+type(error).__name__+' (details withheld)',file=sys.stderr,flush=True)
        print('RELEASE GATE: HOLD / NO-GO.',file=sys.stderr,flush=True)
        sys.exit(1)
