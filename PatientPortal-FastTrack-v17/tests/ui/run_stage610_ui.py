"""Stage 6.10 - isolated UI compatibility test with current Fast Track candidate backend.

No live portal services, no HTTP network listener, no patient or backup data.
Only whitelisted templates/static may be read from an explicitly supplied UI root.
All mutable data is generated in a fresh TemporaryDirectory and then removed.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
from html.parser import HTMLParser
import importlib.util
import io
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import sys
import tempfile
from datetime import date
from contextlib import closing

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parents[1] / 'app'
PIN = __import__('json').loads((ROOT.parents[1] / 'MANIFEST_SHA256.json').read_text(encoding='utf-8'))['app/portal.py']
TEMPLATES = (
    "audit.html", "base.html", "change_password.html", "credentials.html",
    "detail.html", "edit_patient.html", "error.html", "login.html",
    "new_patient.html", "patient.html", "reports.html", "settings.html", "staff.html"
)
STATIC = ("style.css", "portal-ui.js")

class UIParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.stack = []
        self.links = []
        self.viewport = False
        self.styles = []
        self.scripts = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if d.get('id'): self.ids.add(d['id'])
        if tag == 'meta' and d.get('name','').lower() == 'viewport':
            self.viewport = True
        if tag == 'link' and d.get('href'):
            self.styles.append(d['href'])
        if tag == 'script' and d.get('src'):
            self.scripts.append(d['src'])
        if tag == 'a':
            self.links.append(d.get('href',''))
        if tag == 'form':
            f = {'method':d.get('method','get').lower(), 'action':d.get('action',''), 'fields':set()}
            self.forms.append(f)
            self.stack.append(f)
        if tag in ('input','select','textarea') and self.stack and d.get('name'):
            self.stack[-1]['fields'].add(d['name'])

    def handle_endtag(self, tag):
        if tag == 'form' and self.stack:
            self.stack.pop()


def check(cond, label):
    if not cond:
        raise AssertionError(label)
    print('PASS:', label, flush=True)


def load_ui_assets(source_root, destination):
    source = source_root.resolve()
    for folder, names in [('templates', TEMPLATES), ('static',STATIC)]:
        srcdir = source / folder
        if not srcdir.is_dir() or srcdir.is_symlink():
            raise RuntimeError('HOLD: Missing/unsafe UI folder: '+folder)
        (destination / folder).mkdir(parents=True, exist_ok=True)
        for name in names:
            item = srcdir / name
            if not item.is_file() or item.is_symlink():
                raise RuntimeError('HOLD: Missing/unsafe UI asset: '+folder+'/'+name)
            if item.stat().st_size > 1024 * 1024:
                raise RuntimeError('HOLD: Unexpectedly large UI asset: '+folder+'/'+name)
            shutil.copyfile(item, destination / folder / name)
    check(True, 'only whitelisted templates and static assets copied; no .env or patient data')


def page_html(client, route, expect=200):
    response = client.get(route, follow_redirects=False)
    check(response.status_code == expect, f'GET {route} HTTP {expect}')
    assert response.headers.get('cache-control','').startswith('private, no-store'), route
    assert response.headers.get('x-content-type-options') == 'nosniff', route
    parsed = UIParser()
    parsed.feed(response.text)
    check(parsed.viewport, f'{route} has mobile viewport metadata')
    check(any(x.startswith('/static/style.css') for x in parsed.styles), f'{route} references local stylesheet')
    return parsed, response.text


def check_forms(parsed, route):
    posts = [f for f in parsed.forms if f['method'] == 'post']
    check(all(('csrf' in f['fields'] or 'login_token' in f['fields']) for f in posts),
          f'{route} POST forms contain anti-CSRF field')


def run(ui_source):
    actual = hashlib.sha256((SOURCE/'portal.py').read_bytes()).hexdigest()
    check(actual == PIN, 'candidate backend SHA-256 matches manifest')
    fixture = SOURCE
    check(not (fixture/'.env').exists() and not (fixture/'private_data').exists(),
          'package fixture contains no secrets or private data')
    source = ui_source if ui_source is not None else fixture
    check(source.is_dir(), 'UI source directory exists')
    check(not source.is_symlink(), 'UI source root is not a symlink')
    print('INFO: UI source = ' + ('provided UI source (read-only)' if ui_source is not None else 'bundled candidate UI'), flush=True)

    with tempfile.TemporaryDirectory(prefix='portal_stage610_FAKE_ONLY_') as temp:
        home = Path(temp)
        copied = home/'isolated_app'
        copied.mkdir()
        shutil.copyfile(fixture/'portal.py',copied/'portal.py')
        load_ui_assets(source,copied)
        database = home/'synthetic.sqlite3'
        uploads = home/'synthetic_uploads'
        uploads.mkdir()
        original_env = os.environ.copy()
        portal = None
        module_name = 'stage610_synthetic_fixture'
        try:
            os.environ.update({
                'PORTAL_ENV':'development',
                'PORTAL_COOKIE_SECURE':'0',
                'PORTAL_ALLOWED_HOSTS':'testserver',
                'DATABASE_URL':'sqlite:///'+database.as_posix(),
                'PRIVATE_STORAGE':str(uploads),
                'PORTAL_SECRET':secrets.token_urlsafe(56),
            })
            spec=importlib.util.spec_from_file_location(module_name, copied/'portal.py')
            if spec is None or spec.loader is None: raise RuntimeError('Cannot import fake-only source')
            portal=importlib.util.module_from_spec(spec)
            sys.modules[module_name]=portal
            spec.loader.exec_module(portal)
            from fastapi.testclient import TestClient
            from reportlab.pdfgen import canvas
            from sqlalchemy import select
            staff_password=secrets.token_urlsafe(20)
            patient_password=secrets.token_urlsafe(20)
            outsider_password=secrets.token_urlsafe(20)
            pdf_buffer=io.BytesIO()
            canvas_pdf=canvas.Canvas(pdf_buffer)
            canvas_pdf.drawString(40, 750, 'TEST DATA ONLY - STAGE 6.10')
            canvas_pdf.save()
            pdf_bytes=pdf_buffer.getvalue()
            with portal.SessionLocal() as db:
                staff=portal.User(username='S610_STAFF_FAKE',full_name='TEST STAFF',role='staff',active=True,password_hash=portal.ph.hash(staff_password))
                patient=portal.User(username='S610_PATIENT_FAKE',full_name='TEST PATIENT',role='patient',active=True,password_hash=portal.ph.hash(patient_password))
                outsider=portal.User(username='S610_OTHER_FAKE',full_name='TEST OTHER PATIENT',role='patient',active=True,password_hash=portal.ph.hash(outsider_password))
                db.add_all([staff,patient,outsider]); db.commit()
                staff_id, patient_id, outsider_id=staff.id,patient.id,outsider.id
                stored='stage610_synthetic.pdf'
                (uploads/stored).write_bytes(pdf_bytes)
                report=portal.Report(patient_id=patient.id,uploaded_by=staff.id,modality='ЯМР', title='TEST MRI RESULT', exam_date=date(2026,10,28), stored_name=stored, original_name='stage610_fake.pdf', published_at=portal.now(),file_sha256=hashlib.sha256(pdf_bytes).hexdigest())
                db.add(report); db.commit(); report_id=report.id

            def login(client, username, password):
                login_page, html=page_html(client,'/login')
                check_forms(login_page,'/login')
                check('username' in html and 'password' in html,'login form fields rendered')
                token=client.cookies.get('login_csrf')
                check(bool(token), 'synthetic login CSRF cookie issued')
                resp=client.post('/login',data={'username':username,'password':password,'login_token':token},follow_redirects=False)
                check(resp.status_code==303 and resp.headers.get('location')=='/dashboard','synthetic user login redirects')

            with TestClient(portal.app,base_url='http://testserver',follow_redirects=False) as staff_client:
                check(staff_client.get('/dashboard').status_code==303,'unauthenticated dashboard redirects')
                login(staff_client,'S610_STAFF_FAKE',staff_password)
                staff_routes=['/dashboard','/patients/new','/reports','/settings','/audit',f'/patients/{patient_id}',f'/patients/{patient_id}/edit','/change-password']
                for route in staff_routes:
                    parsed, html=page_html(staff_client,route)
                    check_forms(parsed,route)
                check('TEST PATIENT' in staff_client.get('/dashboard').text,'staff patient list displays synthetic patient')
                check('TEST MRI RESULT' in staff_client.get('/reports').text,'staff report list displays synthetic PDF metadata')
                check('csrf' in staff_client.get(f'/patients/{patient_id}').text,'patient detail contains protected forms')
                response=staff_client.get(f'/reports/{report_id}/preview')
                check(response.status_code==200 and response.content.startswith(b'%PDF-'),'staff PDF preview works with UI fixture')
                for route in ['/static/style.css','/static/portal-ui.js']:
                    resp=staff_client.get(route)
                    check(resp.status_code==200 and len(resp.content)>100, f'local asset {route} served')
                style=(copied/'static'/'style.css').read_text(encoding='utf-8')
                js=(copied/'static'/'portal-ui.js').read_text(encoding='utf-8')
                check('@media' in style,'stylesheet includes responsive media rules')
                check('data-file-drop' in js,'PDF drag-drop enhancement present')

            with TestClient(portal.app,base_url='http://testserver',follow_redirects=False) as patient_client:
                login(patient_client,'S610_PATIENT_FAKE',patient_password)
                parsed,html=page_html(patient_client,'/dashboard')
                check_forms(parsed,'patient /dashboard')
                check('TEST MRI RESULT' in html,'patient dashboard lists own published PDF')
                check('/reports' not in [f['action'] for f in parsed.forms if f['method']=='post'], 'no staff upload form in patient dashboard')
                r=patient_client.get(f'/reports/{report_id}/view')
                check(r.status_code==200 and r.content.startswith(b'%PDF-'),'patient embedded PDF view returns actual PDF')
                r=patient_client.get(f'/reports/{report_id}/download')
                check(r.status_code==200 and r.content==pdf_bytes,'patient download matches synthetic PDF bytes')
                check(r.headers.get('content-disposition','').startswith('attachment;'), 'download attachment disposition')
                check(patient_client.get('/reports').status_code==403, 'patient cannot access staff report registry')
                check(patient_client.get('/settings').status_code==403, 'patient cannot access staff settings')
                check(patient_client.get('/audit').status_code==403, 'patient cannot access audit')
                parsed,html=page_html(patient_client,'/change-password')
                check_forms(parsed,'patient /change-password')

            with TestClient(portal.app,base_url='http://testserver',follow_redirects=False) as other_client:
                login(other_client,'S610_OTHER_FAKE',outsider_password)
                check(other_client.get(f'/reports/{report_id}/download').status_code==404,'different patient cannot download protected PDF')
                check(other_client.get(f'/reports/{report_id}/view').status_code==404,'different patient cannot view protected PDF')

            with closing(sqlite3.connect(database.as_posix())) as conn:
                check(conn.execute('PRAGMA integrity_check').fetchone()[0]=='ok','synthetic SQLite integrity OK')
            print('PASS: STAGE6.10 ISOLATED UI COMPATIBILITY COMPLETE',flush=True)
            print('RELEASE GATE: HOLD / NO-GO. Manual visual review and installed UI version evidence still required.',flush=True)
        finally:
            if portal is not None:
                portal.engine.dispose()
            sys.modules.pop(module_name,None)
            os.environ.clear(); os.environ.update(original_env)
            del portal
            gc.collect()


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--ui-source-root',type=Path,default=None,
                   help='Optional directory with templates/ and static/; no other source files are read')
    a=p.parse_args()
    try:
        run(a.ui_source_root)
    except Exception as ex:
        # Avoid displaying secrets, app source, or patient records in exception traces.
        print('HOLD: STAGE6.10 isolated test failed: '+type(ex).__name__+': '+str(ex),file=sys.stderr)
        sys.exit(1)
