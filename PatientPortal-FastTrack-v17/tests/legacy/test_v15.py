"""Regression tests for the v1.5 additive feature set (no real patient data)."""
import io
import re
from PIL import Image
from fastapi.testclient import TestClient
from test_portal import setup_portal, login, csrf_for, minimal_pdf, upload


def test_v15_professional_staff_navigation_and_sorting(setup_portal):
    portal, client, ids = setup_portal
    login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    r=client.get('/dashboard?sort=name_asc&q=%D0%9F%D0%B0%D1%86%D0%B8%D0%B5%D0%BD%D1%82')
    assert r.status_code == 200
    assert 'Медицински център' in r.text
    assert 'Бързи действия' in r.text
    assert 'sort=name_asc' not in r.text or 'selected' in r.text
    assert 'Пациент Втори' in r.text
    assert 'Пациент Първи' in r.text
    assert 'Най-нови' in client.get('/dashboard?sort=invalid').text
    assert '<aside class="side-nav"' in r.text
    assert '＋ PDF' in r.text


def test_v15_settings_csrf_brand_persistence_and_patient_permissions(setup_portal):
    portal, client, ids=setup_portal
    login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(client)
    bad = client.post('/settings',data={'csrf':'bad','center_name':'Тестов Център'},follow_redirects=False)
    assert bad.status_code==403
    ok=client.post('/settings',data={'csrf':csrf,'center_name':'Диагностичен център ТЕСТ',
                           'phone':'02 123 456','email':'info@example.bg','address':'Тестова улица',
                           'website':'https://example.bg'},follow_redirects=False)
    assert ok.status_code==303
    assert ok.headers['location']=='/settings?saved=1'
    assert 'Диагностичен център ТЕСТ' in client.get('/dashboard').text
    assert '02 123 456' in client.get('/settings').text
    with portal.SessionLocal() as db:
        assert db.get(portal.CenterSettings,1).center_name=='Диагностичен център ТЕСТ'
    client.post('/logout',data={'csrf':csrf})
    assert login(client,'patient-one','PATIENT1_PASSWORD_GOOD').status_code==303
    assert 'Диагностичен център ТЕСТ' in client.get('/dashboard').text
    assert client.get('/settings').status_code==403
    assert client.post('/settings',data={'center_name':'HACK'}).status_code==403


def test_v15_logo_validated_reencoded_and_isolated(setup_portal):
    portal, client, ids=setup_portal
    login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(client)
    no=client.post('/settings/logo', data={'csrf':csrf},files={'logo':('bad.svg',b'<svg />','image/svg+xml')})
    assert no.status_code==422
    img=Image.new('RGB',(220,55),color='#1a70b7')
    memory=io.BytesIO();img.save(memory,format='JPEG')
    yes=client.post('/settings/logo',data={'csrf':csrf},files={'logo':('brand.jpg',memory.getvalue(),'image/jpeg')}, follow_redirects=False)
    assert yes.status_code==303
    logo=client.get('/center-logo')
    assert logo.status_code==200 and logo.headers['content-type']=='image/png'
    assert logo.content.startswith(b'\x89PNG')
    with portal.SessionLocal() as db:
        config=db.get(portal.CenterSettings,1)
        assert re.fullmatch(r'brand_[a-f0-9]{24}\.png', config.logo_filename)
    client.post('/logout',data={'csrf':csrf})
    assert client.get('/center-logo').status_code==200  # login page branding


def test_v15_pdf_duplicates_and_old_file_cleanup(setup_portal):
    portal, client, ids=setup_portal
    login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(client)
    content=minimal_pdf()
    first=upload(client,ids['p1'],csrf,data=content,publish=False)
    assert first.status_code==303
    second=upload(client,ids['p1'],csrf,data=content,publish=False)
    assert second.status_code==409
    with portal.SessionLocal() as db:
        assert db.query(portal.Report).count()==1
        report=db.query(portal.Report).one()
        assert len(report.file_sha256)==64
    assert len(list(portal.STORAGE.glob('*.pdf')))==1
    assert upload(client,ids['p2'],csrf,data=content,publish=False).status_code==303
    assert len(list(portal.STORAGE.glob('*.pdf')))==2


def test_v15_patient_view_only_published_own_reports(setup_portal):
    portal, admin, ids=setup_portal
    login(admin,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(admin)
    upload(admin,ids['p1'],csrf,publish=False)
    with portal.SessionLocal() as db: rid=db.query(portal.Report).one().id
    admin.post('/logout',data={'csrf':csrf})
    login(admin,'patient-one','PATIENT1_PASSWORD_GOOD')
    assert admin.get(f'/reports/{rid}/view').status_code==404
    admin.post('/logout',data={'csrf':csrf_for(admin)})
    login(admin,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(admin)
    assert admin.get(f'/reports/{rid}/preview').status_code==200
    assert admin.post(f'/reports/{rid}/publish',data={'csrf':csrf,'confirm_owner':'yes'},follow_redirects=False).status_code==303
    admin.post('/logout',data={'csrf':csrf})
    login(admin,'patient-two','PATIENT2_PASSWORD_GOOD')
    assert admin.get(f'/reports/{rid}/view').status_code==404
    admin.post('/logout',data={'csrf':csrf_for(admin)})
    login(admin,'patient-one','PATIENT1_PASSWORD_GOOD')
    page=admin.get('/dashboard')
    assert f'/reports/{rid}/view' in page.text
    r=admin.get(f'/reports/{rid}/view')
    assert r.status_code==200 and 'inline' in r.headers['content-disposition']
    assert r.content.startswith(b'%PDF-')


def test_v15_pdf_branding_and_settings_input_rejection(setup_portal):
    from pypdf import PdfReader
    portal, client, ids=setup_portal
    login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(client)
    assert client.post('/settings',data={'csrf':csrf,'center_name':'Нашия Център','website':'javascript:alert(1)'}).status_code==422
    assert client.post('/settings',data={'csrf':csrf,'center_name':'Нашия Център','website':'https://example.bg','phone':'032 333333'},follow_redirects=False).status_code==303
    created=client.post('/patients/new',data={'csrf':csrf,'full_name':'Тест Печат','identifier':'9001010000','identifier_type':'EGN'})
    uname,pwd=re.findall(r'<strong class="mono(?: secret-text)?">([^<]+)</strong>',created.text)
    with portal.SessionLocal() as db:
        pid=db.query(portal.User).filter_by(username=uname).one().id
    pdf=client.post(f'/patients/{pid}/credentials-pdf',data={'csrf':csrf,'password':pwd})
    assert pdf.status_code==200
    text=PdfReader(io.BytesIO(pdf.content)).pages[0].extract_text()
    assert 'Нашия Център' in text and 'Пациентски портал' in text and uname in text and pwd in text
    assert '032 333333' in text


def test_v15_upgrade_v14_sqlite_preserves_legacy_users_and_reports(monkeypatch,tmp_path):
    """Upgrade in place: same ids, password hash, original PDF path, published timestamp."""
    import sqlite3, sys, importlib
    from argon2 import PasswordHasher
    old=tmp_path/'old_v14.sqlite3'
    uploads=tmp_path/'uploads'; uploads.mkdir()
    (uploads/'existing.pdf').write_bytes(minimal_pdf())
    hash_before=PasswordHasher().hash('LEGACY_PASSWORD_KEEP_1234')
    with sqlite3.connect(old) as conn:
        conn.executescript('''
        CREATE TABLE users(id INTEGER PRIMARY KEY,username VARCHAR(80) UNIQUE,full_name VARCHAR(160),
           password_hash VARCHAR(255),role VARCHAR(16),active BOOLEAN,must_change_password BOOLEAN,created_at DATETIME);
        CREATE TABLE reports(id INTEGER PRIMARY KEY,patient_id INTEGER,uploaded_by INTEGER,
           modality VARCHAR(20),title VARCHAR(120),exam_date DATE,stored_name VARCHAR(60) UNIQUE,
           original_name VARCHAR(180),uploaded_at DATETIME,revoked_at DATETIME,published_at DATETIME);
        CREATE TABLE audit(id INTEGER PRIMARY KEY,actor_id INTEGER,action VARCHAR(40),target_id INTEGER,
           occurred_at DATETIME,details VARCHAR(250));
        ''')
        dt='2026-10-01 10:00:00.000000'
        conn.execute('INSERT INTO users VALUES (1,?,?,?,?,?,?,?)',('old-patient','Пациент от v1.4',hash_before,'patient',1,0,dt))
        conn.execute('INSERT INTO users VALUES (2,?,?,?,?,?,?,?)',('old-staff','Служител от v1.4',PasswordHasher().hash('STAFF_PASSWORD_123456789'),'staff',1,0,dt))
        conn.execute('INSERT INTO reports VALUES(1,1,2,?,?,?,?,?,?,?,?)',
                     ('ЯМР','Стар публикуван PDF','2026-10-01','existing.pdf','existing.pdf',dt,None,dt))
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{old}')
    monkeypatch.setenv('PRIVATE_STORAGE',str(uploads))
    monkeypatch.setenv('PORTAL_SECRET','UPGRADE_TEST_SECRET_123456789012345')
    monkeypatch.setenv('PORTAL_ALLOWED_HOSTS','testserver')
    sys.modules.pop('portal',None)
    portal=importlib.import_module('portal')
    with portal.SessionLocal() as db:
        u=db.get(portal.User,1);doc=db.get(portal.Report,1)
        assert u.username=='old-patient' and u.password_hash==hash_before
        assert portal.ph.verify(u.password_hash,'LEGACY_PASSWORD_KEEP_1234')
        assert doc.stored_name=='existing.pdf' and doc.published_at and doc.file_sha256 is None
        assert db.get(portal.CenterSettings,1) is None
    portal.migrate_v14_schema()
    with TestClient(portal.app) as client:
        assert login(client,'old-patient','LEGACY_PASSWORD_KEEP_1234').status_code==303
        assert 'Стар публикуван PDF' in client.get('/dashboard').text
        assert client.get('/reports/1/download').status_code==200
    sys.modules.pop('portal',None)
