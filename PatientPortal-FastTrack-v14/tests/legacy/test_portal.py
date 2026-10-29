import importlib
import io
import re
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def setup_portal(monkeypatch, tmp_path):
    monkeypatch.setenv("PORTAL_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'portal.sqlite3'}")
    monkeypatch.setenv("PRIVATE_STORAGE", str(tmp_path / "uploads"))
    monkeypatch.setenv("PORTAL_ALLOWED_HOSTS", "testserver")
    monkeypatch.setenv("PORTAL_SECRET", "TEST_SECRET_NOT_FOR_PRODUCTION_" * 2)
    sys.modules.pop("portal", None)
    portal = importlib.import_module("portal")
    with portal.SessionLocal() as db:
        a = portal.User(username="admin-staff", full_name="Служител",
                        password_hash=portal.ph.hash("STAFF_PASSWORD_GOOD_1234"), role="staff", active=True)
        p1 = portal.User(username="patient-one", full_name="Пациент Първи",
                         password_hash=portal.ph.hash("PATIENT1_PASSWORD_GOOD"), role="patient", active=True)
        p2 = portal.User(username="patient-two", full_name="Пациент Втори",
                         password_hash=portal.ph.hash("PATIENT2_PASSWORD_GOOD"), role="patient", active=True)
        db.add_all([a, p1, p2]); db.commit()
        ids = {"staff": a.id, "p1": p1.id, "p2": p2.id}
    with TestClient(portal.app) as client:
        yield portal, client, ids
    sys.modules.pop("portal", None)


def login(client, username, pwd):
    r = client.get("/login")
    assert r.status_code == 200
    token = re.search(r'name="login_token" value="([^"]+)"', r.text).group(1)
    return client.post("/login", data={"username": username, "password": pwd, "login_token": token}, follow_redirects=False)


def csrf_for(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    return re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)


def minimal_pdf():
    # Valid PDF bytes generated locally; not a real medical result.
    from pypdf import PdfWriter
    w = PdfWriter(); w.add_blank_page(width=400, height=400)
    data = io.BytesIO(); w.write(data)
    return data.getvalue()


def upload(client, patient_id, csrf, data=None, form_override=None, publish=True):
    args = {"title":"ЯМР на глава", "modality":"ЯМР", "exam_date":"2026-10-01", "csrf":csrf, "confirm_owner":"yes"}
    if form_override: args.update(form_override)
    response = client.post(f"/patients/{patient_id}/reports", data=args,
                           files={"file": ("result.pdf", data if data is not None else minimal_pdf(), "application/pdf")},
                           follow_redirects=False)
    # Legacy tests exercise the same published-document behavior as v1.3;
    # new workflow tests call publish=False to test draft isolation explicitly.
    if publish and response.status_code == 303:
        portal = sys.modules['portal']
        with portal.SessionLocal() as db:
            report = db.scalar(portal.select(portal.Report).where(portal.Report.patient_id == patient_id)
                               .order_by(portal.Report.id.desc()))
            assert report is not None
            assert client.get(f'/reports/{report.id}/preview').status_code == 200
            pub = client.post(f'/reports/{report.id}/publish',
                              data={'csrf':csrf,'confirm_owner':'yes'}, follow_redirects=False)
            assert pub.status_code == 303, pub.text
    return response


def test_permissions_and_upload(setup_portal):
    portal, client, ids = setup_portal
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    assert login(client, "admin-staff", "STAFF_PASSWORD_GOOD_1234").status_code == 303
    csrf = csrf_for(client)
    assert upload(client, ids['p1'], csrf).status_code == 303
    with portal.SessionLocal() as db:
        doc = db.query(portal.Report).one()
        doc_id = doc.id
        assert doc.patient_id == ids['p1']
    r = client.get(f"/reports/{doc_id}/download")
    assert r.status_code == 200 and r.content.startswith(b"%PDF-")
    assert r.headers.get('content-disposition','').startswith('attachment')
    assert r.headers['cache-control'].startswith('private, no-store')
    client.post("/logout", data={"csrf": csrf})
    assert login(client, "patient-two", "PATIENT2_PASSWORD_GOOD").status_code == 303
    assert client.get(f"/reports/{doc_id}/download").status_code == 404
    assert f"/patients/{ids['p1']}" not in client.get('/dashboard').text
    assert client.get(f"/patients/{ids['p1']}").status_code == 403
    assert client.get('/audit').status_code == 403
    client.post('/logout', data={"csrf":csrf_for(client)})
    assert login(client, "patient-one", "PATIENT1_PASSWORD_GOOD").status_code == 303
    assert client.get(f"/reports/{doc_id}/download").status_code == 200


def test_csrf_mismatch_and_wrong_pdf(setup_portal):
    portal, client, ids = setup_portal
    login(client, "admin-staff", "STAFF_PASSWORD_GOOD_1234")
    assert upload(client, ids['p1'], 'wrong').status_code == 403
    csrf = csrf_for(client)
    assert upload(client, ids['p1'], csrf, data=b'not a pdf').status_code == 422
    assert upload(client, ids['p1'], csrf, form_override={"confirm_owner":""}).status_code == 422
    with portal.SessionLocal() as db:
        assert db.query(portal.Report).count() == 0
    assert not list(portal.STORAGE.glob('*.pdf'))


def test_revocation_and_disabling(setup_portal):
    portal, client, ids = setup_portal
    login(client, "admin-staff", "STAFF_PASSWORD_GOOD_1234")
    csrf = csrf_for(client)
    upload(client, ids['p1'], csrf)
    with portal.SessionLocal() as db:
        docid = db.query(portal.Report).one().id
    r = client.post(f'/reports/{docid}/revoke', data={'csrf':csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get(f'/reports/{docid}/download').status_code == 404
    client.post(f'/patients/{ids["p1"]}/status', data={'csrf':csrf})
    client.post('/logout', data={'csrf':csrf})
    assert login(client, "patient-one", "PATIENT1_PASSWORD_GOOD").status_code == 401


def test_generated_patient_password_persists_across_logins(setup_portal):
    portal, client, ids = setup_portal
    login(client, "admin-staff", "STAFF_PASSWORD_GOOD_1234")
    csrf = csrf_for(client)
    response = client.post('/patients/new', data={'full_name':'Нов Пациент','identifier':'9001010000','identifier_type':'EGN','csrf':csrf})
    assert response.status_code == 200 and 'генерирана парола' in response.text.lower()
    creds = re.findall(r'<strong class="mono(?: secret-text)?">([^<]+)</strong>', response.text)
    assert len(creds) == 2
    username,password = creds
    client.post('/logout',data={'csrf':csrf})
    first_login = login(client, username, password)
    assert first_login.status_code == 303 and first_login.headers['location'] == '/dashboard'
    assert client.get('/dashboard').status_code == 200
    # The generated password continues to work on subsequent logins.
    client.post('/logout', data={'csrf': csrf_for(client)})
    second_login = login(client, username, password)
    assert second_login.status_code == 303 and second_login.headers['location'] == '/dashboard'
    assert client.get('/dashboard').status_code == 200
    with portal.SessionLocal() as db:
        person = db.query(portal.User).filter_by(username=username).one()
        assert not person.must_change_password


def test_new_patient_can_logout_and_csrf_required(setup_portal):
    portal, client, ids = setup_portal
    login(client, "admin-staff", "STAFF_PASSWORD_GOOD_1234")
    csrf = csrf_for(client)
    response = client.post('/patients/new', data={'full_name':'Втори Тест','identifier':'9001010015','identifier_type':'EGN','csrf':csrf})
    creds = re.findall(r'<strong class="mono(?: secret-text)?">([^<]+)</strong>', response.text)
    username, password = creds
    client.post('/logout', data={'csrf':csrf})
    assert login(client, username, password).status_code == 303
    patient_csrf = csrf_for(client)
    assert client.post('/logout', data={'csrf':'invalid'}).status_code == 403
    logout_response = client.post('/logout', data={'csrf':patient_csrf}, follow_redirects=False)
    assert logout_response.status_code == 303
    assert client.get('/dashboard', follow_redirects=False).status_code == 303


def test_egn_lnch_validation_and_duplicate(setup_portal):
    portal, client, ids = setup_portal
    assert portal.valid_patient_identifier('9001010000', 'EGN')
    assert not portal.valid_patient_identifier('9001010001', 'EGN')
    assert not portal.valid_patient_identifier('9913310000', 'EGN')
    assert portal.valid_patient_identifier('1234567893', 'LNCH')
    assert not portal.valid_patient_identifier('1234567890', 'LNCH')
    assert not portal.valid_patient_identifier('9001010000', 'NOT_DEFINED')
    login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234')
    csrf = csrf_for(client)
    for identifier, kind in [('abc', 'EGN'), ('9001010001', 'EGN'), ('1234567890', 'LNCH')]:
        r = client.post('/patients/new', data={'full_name': 'Тестов Пациент', 'identifier': identifier,
                                                 'identifier_type':kind,'csrf':csrf})
        assert r.status_code == 422
    r = client.post('/patients/new', data={'full_name':'Тестов Пациент','identifier':'1234567893',
                                           'identifier_type':'LNCH','csrf':csrf})
    assert r.status_code == 200
    with portal.SessionLocal() as db:
        p = db.query(portal.User).filter_by(username='1234567893').one()
        assert p.role == 'patient' and not p.must_change_password
    r = client.post('/patients/new', data={'full_name':'Дублаж','identifier':'1234567893',
                                           'identifier_type':'LNCH','csrf':csrf})
    assert r.status_code == 422 and 'съществува' in r.text


def test_credentials_pdf_is_downloadable_printable_and_protected(setup_portal):
    from pypdf import PdfReader
    portal, client, ids = setup_portal
    login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234')
    csrf = csrf_for(client)
    response = client.post('/patients/new',data={'full_name':'PDF Тест','identifier':'9001010000',
                       'identifier_type':'EGN','csrf':csrf})
    assert response.status_code == 200
    username,password = re.findall(r'<strong class="mono(?: secret-text)?">([^<]+)</strong>',response.text)
    assert username == '9001010000'
    with portal.SessionLocal() as db:
        patient = db.query(portal.User).filter_by(username=username).one()
        pid = patient.id
    url = f'/patients/{pid}/credentials-pdf'
    assert client.post(url,data={'csrf':'bad','password':password}).status_code == 403
    assert client.post(url,data={'csrf':csrf,'password':'bad'}).status_code == 403
    r = client.post(url,data={'csrf':csrf,'password':password,'disposition':'attachment'})
    assert r.status_code == 200
    assert r.content.startswith(b'%PDF-')
    assert r.headers['content-disposition'].startswith('attachment')
    page = PdfReader(io.BytesIO(r.content)).pages[0].extract_text()
    assert '9001010000' in page and password in page and 'Пациентски портал' in page
    r = client.post(url,data={'csrf':csrf,'password':password,'disposition':'inline'})
    assert r.status_code == 200 and r.headers['content-disposition'].startswith('inline')
    assert 'no-store' in r.headers['cache-control']
    assert not list(portal.STORAGE.glob('*.pdf'))
    client.post(f'/patients/{pid}/reset',data={'csrf':csrf})
    assert client.post(url,data={'csrf':csrf,'password':password}).status_code == 403
    client.post('/logout',data={'csrf':csrf})
    login(client,'patient-one','PATIENT1_PASSWORD_GOOD')
    assert client.post(url,data={'csrf':csrf,'password':password}).status_code in (403, 303)


def test_legacy_patient_flag_does_not_force_change(setup_portal):
    portal, client, ids = setup_portal
    with portal.SessionLocal() as db:
        person = db.get(portal.User, ids['p1'])
        person.must_change_password = True  # Simulate an existing v1.2 patient.
        db.commit()
    r = login(client, 'patient-one', 'PATIENT1_PASSWORD_GOOD')
    assert r.status_code == 303 and r.headers['location'] == '/dashboard'
    assert client.get('/dashboard').status_code == 200
    client.post('/logout', data={'csrf': csrf_for(client)})
    r = login(client, 'patient-one', 'PATIENT1_PASSWORD_GOOD')
    assert r.headers['location'] == '/dashboard'


def test_staff_demo_password_still_needs_change(setup_portal):
    portal, client, ids = setup_portal
    with portal.SessionLocal() as db:
        person = db.get(portal.User, ids['staff'])
        person.must_change_password = True
        db.commit()
    result = login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234')
    assert result.status_code == 303 and result.headers['location'] == '/change-password'
    assert client.get('/dashboard', follow_redirects=False).headers['location'] == '/change-password'


def test_reset_password_stays_valid_and_pdf_can_be_exported(setup_portal):
    portal, client, ids = setup_portal
    login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234')
    csrf = csrf_for(client)
    reset = client.post(f"/patients/{ids['p1']}/reset", data={'csrf':csrf})
    assert reset.status_code == 200
    username, password = re.findall(r'<strong class="mono(?: secret-text)?">([^<]+)</strong>', reset.text)
    assert username == 'patient-one'
    output = client.post(f"/patients/{ids['p1']}/credentials-pdf", data={'csrf':csrf,'password':password})
    assert output.status_code == 200 and output.content.startswith(b'%PDF-')
    client.post('/logout', data={'csrf':csrf})
    assert login(client, username, password).headers['location'] == '/dashboard'
    client.post('/logout', data={'csrf':csrf_for(client)})
    assert login(client, username, password).headers['location'] == '/dashboard'
    with portal.SessionLocal() as db:
        person = db.get(portal.User, ids['p1'])
        assert not person.must_change_password

# v1.3 regression tests — no schema changes to v1.2.2

def test_v13_staff_filters_and_escaped_search(setup_portal):
    portal, client, ids = setup_portal
    assert login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234').status_code == 303
    csrf = csrf_for(client)
    assert upload(client, ids['p1'], csrf).status_code == 303
    response = client.get('/dashboard?documents=with')
    assert response.status_code == 200
    assert 'Пациент Първи' in response.text and 'Пациент Втори' not in response.text
    response = client.get('/dashboard?documents=without')
    assert 'Пациент Втори' in response.text.split('Последно качени разчитания')[0] and 'Пациент Първи' not in response.text.split('Последно качени разчитания')[0]
    client.post(f'/patients/{ids["p2"]}/status',data={'csrf':csrf})
    response = client.get('/dashboard?status=inactive')
    assert 'Пациент Втори' in response.text.split('Последно качени разчитания')[0] and 'Пациент Първи' not in response.text.split('Последно качени разчитания')[0]
    # A literal LIKE wildcard must not mean 'all patients'.
    assert 'Пациент Първи' not in client.get('/dashboard?q=%25').text.split('Последно качени разчитания')[0]
    assert 'Пациент Първи' not in client.get('/dashboard?q=_').text.split('Последно качени разчитания')[0]
    assert client.get('/dashboard?page_num=-99').status_code == 200
    assert client.get('/dashboard?page_num=9999999').status_code == 200
    assert 'script-src \'self\'' in response.headers['content-security-policy']


def test_v13_report_listing_and_revoke(setup_portal):
    portal, client, ids = setup_portal
    login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234')
    csrf = csrf_for(client)
    assert upload(client, ids['p1'], csrf).status_code == 303
    assert upload(client, ids['p2'], csrf, form_override={'modality':'КТ', 'title':'КТ на глава'}).status_code == 303
    response = client.get('/reports?modality=%D0%AF%D0%9C%D0%A0&status=active')
    assert response.status_code == 200
    assert 'Пациент Първи' in response.text and 'Пациент Втори' not in response.text
    with portal.SessionLocal() as db:
        docid = db.query(portal.Report).filter_by(patient_id=ids['p1']).one().id
    client.post(f'/reports/{docid}/revoke', data={'csrf':csrf})
    response = client.get('/reports?status=revoked')
    assert 'Пациент Първи' in response.text and 'Пациент Втори' not in response.text
    assert client.get(f'/reports/{docid}/download').status_code == 404
    assert client.get('/static/portal-ui.js').status_code == 200


def test_v13_patient_cannot_access_admin_reports(setup_portal):
    portal, client, ids = setup_portal
    assert login(client, 'patient-one', 'PATIENT1_PASSWORD_GOOD').status_code == 303
    assert client.get('/reports').status_code == 403
    assert client.get('/patients/2').status_code == 403
    assert client.get('/dashboard?status=inactive&documents=with').status_code == 200
    assert 'Управление на пациенти' not in client.get('/dashboard').text


def test_v13_dashboard_pagination_and_backward_compatibility(setup_portal):
    portal, client, ids = setup_portal
    with portal.SessionLocal() as db:
        for i in range(29):
            db.add(portal.User(username=f'test-{i:03}', full_name=f'Тест {i:03}',
                 password_hash=portal.ph.hash('TEST_PASSWORD_GOOD_2026'),role='patient',active=True))
        db.commit()
    login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234')
    first = client.get('/dashboard?page_num=1')
    second = client.get('/dashboard?page_num=2')
    assert first.status_code == 200 and second.status_code == 200
    assert 'Страница 1 от 2' in first.text and 'Страница 2 от 2' in second.text
    assert 'Тест 028' in first.text and 'Тест 000' in second.text
    assert client.get('/reports').status_code == 200
    with portal.SessionLocal() as db:
        assert db.query(portal.User).filter_by(role='patient').count() == 31

# v1.4 staged publishing, editing, logging and automatic SQLite migration

def test_v14_draft_preview_publish_and_patient_isolation(setup_portal):
    portal, client, ids = setup_portal
    assert login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234').status_code == 303
    csrf = csrf_for(client)
    assert upload(client, ids['p1'], csrf, publish=False).status_code == 303
    with portal.SessionLocal() as db:
        doc = db.query(portal.Report).one()
        doc_id = doc.id
        assert doc.published_at is None
        assert doc.revoked_at is None
    assert 'Чернова' in client.get(f'/patients/{ids["p1"]}').text
    assert 'Пациент Първи' in client.get('/reports?status=draft').text
    assert 'Пациент Първи' not in client.get('/reports?status=active').text
    preview = client.get(f'/reports/{doc_id}/preview')
    assert preview.status_code == 200 and preview.content.startswith(b'%PDF-')
    assert preview.headers['content-disposition'].startswith('inline')
    assert 'no-store' in preview.headers['cache-control']
    assert client.post(f'/reports/{doc_id}/publish', data={'csrf':'wrong','confirm_owner':'yes'}).status_code == 403
    assert client.post(f'/reports/{doc_id}/publish', data={'csrf':csrf}).status_code == 422
    client.post('/logout', data={'csrf':csrf})
    assert login(client, 'patient-one', 'PATIENT1_PASSWORD_GOOD').status_code == 303
    assert 'ЯМР на глава' not in client.get('/dashboard').text
    assert client.get(f'/reports/{doc_id}/download').status_code == 404
    assert client.get(f'/reports/{doc_id}/preview').status_code == 403
    assert client.post(f'/reports/{doc_id}/publish', data={'csrf':csrf,'confirm_owner':'yes'}).status_code == 403
    client.post('/logout', data={'csrf':csrf_for(client)})
    login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234')
    csrf = csrf_for(client)
    assert client.post(f'/reports/{doc_id}/publish', data={'csrf':csrf,'confirm_owner':'yes'},
                       follow_redirects=False).status_code == 303
    assert client.post(f'/reports/{doc_id}/publish', data={'csrf':csrf,'confirm_owner':'yes'}).status_code == 409
    assert 'Пациент Първи' in client.get('/reports?status=active').text
    client.post('/logout', data={'csrf':csrf})
    login(client, 'patient-one', 'PATIENT1_PASSWORD_GOOD')
    assert 'ЯМР на глава' in client.get('/dashboard').text
    assert client.get(f'/reports/{doc_id}/download').status_code == 200


def test_v14_patient_edit_validation_duplicate_and_session_invalidation(setup_portal):
    portal, admin_client, ids = setup_portal
    from fastapi.testclient import TestClient
    with TestClient(portal.app) as patient_client:
        assert login(patient_client, 'patient-one', 'PATIENT1_PASSWORD_GOOD').status_code == 303
        assert login(admin_client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234').status_code == 303
        csrf = csrf_for(admin_client)
        url = f'/patients/{ids["p1"]}/edit'
        assert admin_client.get(url).status_code == 200
        assert patient_client.get(url).status_code == 403
        for payload, expected in [
            ({'full_name':'Нов пациент','identifier':'9001010001','identifier_type':'EGN','confirm_identifier':'yes'},422),
            ({'full_name':'Нов пациент','identifier':'9001010000','identifier_type':'EGN'},422),
            ({'full_name':'','identifier':'patient-one','identifier_type':'EGN'},422),
        ]:
            assert admin_client.post(url, data={'csrf':csrf, **payload}).status_code == expected
        assert admin_client.post(url, data={'csrf':'bad','full_name':'Променен',
                          'identifier':'9001010000','identifier_type':'EGN','confirm_identifier':'yes'}).status_code == 403
        response = admin_client.post(url, data={'csrf':csrf,'full_name':'Нов Тестов Пациент',
                          'identifier':'9001010000','identifier_type':'EGN','confirm_identifier':'yes'},
                          follow_redirects=False)
        assert response.status_code == 303
        with portal.SessionLocal() as db:
            p = db.get(portal.User, ids['p1'])
            assert p.username == '9001010000' and p.full_name == 'Нов Тестов Пациент'
            assert portal.ph.verify(p.password_hash, 'PATIENT1_PASSWORD_GOOD')
            assert db.scalar(portal.select(portal.func.count(portal.LoginSession.id)).where(
                portal.LoginSession.user_id == ids['p1'])) == 0
            entry = db.scalar(portal.select(portal.Audit).where(portal.Audit.action == 'patient_edited'))
            assert 'ЕГН/ЛНЧ' in entry.details and '9001010000' not in entry.details
        assert patient_client.get('/dashboard', follow_redirects=False).headers['location'] == '/login'
        assert login(patient_client,'patient-one','PATIENT1_PASSWORD_GOOD').status_code == 401
        assert login(patient_client,'9001010000','PATIENT1_PASSWORD_GOOD').status_code == 303
        # Existing identifier change to duplicate user is rejected.
        response = admin_client.post(f'/patients/{ids["p2"]}/edit', data={'csrf':csrf,
                 'full_name':'Друг Тест','identifier':'9001010000','identifier_type':'EGN',
                 'confirm_identifier':'yes'})
        assert response.status_code == 422


def test_v14_audit_labels_and_draft_revoke(setup_portal):
    portal, client, ids = setup_portal
    login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(client)
    upload(client, ids['p1'], csrf, publish=False)
    with portal.SessionLocal() as db:
        docid=db.query(portal.Report).one().id
    assert client.get('/audit?action=report_draft_created').status_code == 200
    assert 'Създадена чернова' in client.get('/audit?action=report_draft_created').text
    assert 'Служител' in client.get('/audit').text
    assert client.post(f'/reports/{docid}/revoke',data={'csrf':csrf},follow_redirects=False).status_code == 303
    assert client.post(f'/reports/{docid}/publish',data={'csrf':csrf,'confirm_owner':'yes'}).status_code == 404
    assert client.get(f'/reports/{docid}/preview').status_code == 404
    assert client.get('/reports?status=revoked').status_code == 200
    assert 'Пациент Първи' in client.get('/reports?status=revoked').text


def test_v14_legacy_db_migration_preserves_published_reports(monkeypatch, tmp_path):
    import sqlite3
    from argon2 import PasswordHasher
    dbpath = tmp_path / 'legacy.sqlite3'
    monkeypatch.setenv('PORTAL_ENV','development')
    monkeypatch.setenv('DATABASE_URL',f'sqlite:///{dbpath}')
    monkeypatch.setenv('PRIVATE_STORAGE',str(tmp_path / 'uploads'))
    monkeypatch.setenv('PORTAL_SECRET','MIGRATE_TEST_SECRET_LONG_ENOUGH_12345678')
    (tmp_path/'uploads').mkdir()
    (tmp_path/'uploads'/'legacy.pdf').write_bytes(minimal_pdf())
    # Old v1.3 tables: no published_at on reports, no details on audit.
    with sqlite3.connect(dbpath) as con:
        con.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, username VARCHAR(80) NOT NULL UNIQUE,
          full_name VARCHAR(160) NOT NULL, password_hash VARCHAR(255) NOT NULL,
          role VARCHAR(16) NOT NULL, active BOOLEAN NOT NULL,
          must_change_password BOOLEAN NOT NULL, created_at DATETIME NOT NULL);
        CREATE TABLE reports (id INTEGER PRIMARY KEY, patient_id INTEGER NOT NULL,
          uploaded_by INTEGER NOT NULL, modality VARCHAR(20) NOT NULL,
          title VARCHAR(120) NOT NULL, exam_date DATE NOT NULL,
          stored_name VARCHAR(60) NOT NULL UNIQUE, original_name VARCHAR(180) NOT NULL,
          uploaded_at DATETIME NOT NULL, revoked_at DATETIME);
        CREATE TABLE audit (id INTEGER PRIMARY KEY, actor_id INTEGER, action VARCHAR(40) NOT NULL,
          target_id INTEGER, occurred_at DATETIME NOT NULL);
        """)
        now_s = '2026-10-01 10:00:00.000000'
        for uid, uname, name, pw, role in (
                (1,'legacy-patient','Стар Пациент','LEGACY_PASSWORD_OK_123','patient'),
                (2,'legacy-staff','Стар Служител','LEGACY_ADMIN_PASSWORD_OK_123','staff')):
            con.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?,?)',
                       (uid,uname,name,PasswordHasher().hash(pw),role,1,0,now_s))
        con.execute('INSERT INTO reports VALUES(?,?,?,?,?,?,?,?,?,?)',
                  (1,1,2,'ЯМР','Старо разчитане','2026-10-01','legacy.pdf','legacy.pdf',now_s,None))
        con.execute('INSERT INTO audit VALUES(?,?,?,?,?)',(1,2,'report_uploaded',1,now_s))
        assert 'published_at' not in [x[1] for x in con.execute('PRAGMA table_info(reports)')]
    sys.modules.pop('portal',None)
    new=importlib.import_module('portal')
    with new.SessionLocal() as db:
        doc=db.query(new.Report).one()
        assert doc.published_at is not None
        assert doc.revoked_at is None
        assert db.get(new.User,1).username=='legacy-patient'
        assert new.ph.verify(db.get(new.User,2).password_hash,'LEGACY_ADMIN_PASSWORD_OK_123')
        assert db.query(new.Audit).one().details is None
    new.migrate_v14_schema()  # Idempotency.
    with TestClient(new.app) as client:
        login(client,'legacy-patient','LEGACY_PASSWORD_OK_123')
        assert 'Старо разчитане' in client.get('/dashboard').text
        assert client.get('/reports/1/download').status_code==200
    sys.modules.pop('portal',None)


def test_v14_publish_requires_staff_pdf_preview(setup_portal):
    portal, client, ids = setup_portal
    login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234')
    csrf=csrf_for(client)
    upload(client,ids['p1'],csrf,publish=False)
    with portal.SessionLocal() as db:
        report=db.query(portal.Report).one()
        rid=report.id
    assert client.post(f'/reports/{rid}/publish',
              data={'csrf':csrf,'confirm_owner':'yes'}).status_code == 422
    with portal.SessionLocal() as db:
        assert db.get(portal.Report,rid).published_at is None
    assert client.get(f'/reports/{rid}/preview').status_code == 200
    assert client.post(f'/reports/{rid}/publish',
              data={'csrf':csrf,'confirm_owner':'yes'},follow_redirects=False).status_code == 303
