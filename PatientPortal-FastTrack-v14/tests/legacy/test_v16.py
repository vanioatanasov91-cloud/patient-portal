"""v1.6 regression tests (synthetic profiles and files ONLY)."""
import io
import os
import re
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_portal import setup_portal, login, csrf_for, minimal_pdf, upload


def test_totp_reference_vectors_and_encryption(setup_portal):
    portal, client, ids = setup_portal
    # RFC 6238 example (6 digits, SHA1, TOTP 59s = 287082)
    raw = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    assert portal.totp_now(raw, 59) == '287082'
    assert portal.verify_totp(raw, '287082', tick=59)
    assert not portal.verify_totp(raw, '287083', tick=59)
    ciphertext = portal.encrypt_mfa_secret(raw)
    assert raw not in ciphertext
    assert portal.decrypt_mfa_secret(ciphertext) == raw
    assert 'name="mfa_code"' in client.get('/login').text
    assert login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234').status_code == 303


def test_enrolled_staff_totp_required_but_patients_keep_stable_password(setup_portal):
    portal, client, ids = setup_portal
    token = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    with portal.SessionLocal() as db:
        staff = db.get(portal.User, ids['staff'])
        staff.mfa_secret_enc = portal.encrypt_mfa_secret(token)
        db.commit()
    assert login(client, 'admin-staff', 'STAFF_PASSWORD_GOOD_1234').status_code == 401
    login_form = client.get('/login')
    csrf = re.search(r'name="login_token" value="([^"]+)"', login_form.text).group(1)
    good = client.post('/login',data={'username':'admin-staff','password':'STAFF_PASSWORD_GOOD_1234',
                          'login_token':csrf,'mfa_code':portal.totp_now(token)},follow_redirects=False)
    assert good.status_code == 303
    client.post('/logout',data={'csrf':csrf_for(client)})
    assert login(client,'patient-one','PATIENT1_PASSWORD_GOOD').status_code == 303
    assert client.get('/dashboard').status_code == 200


def test_production_rejects_plain_http_and_unenrolled_staff(monkeypatch, tmp_path):
    monkeypatch.setenv('DATABASE_URL',f"sqlite:///{tmp_path / 'portal.sqlite3'}")
    monkeypatch.setenv('PRIVATE_STORAGE',str(tmp_path/'uploads'))
    monkeypatch.setenv('PORTAL_ENV','production')
    monkeypatch.setenv('PORTAL_COOKIE_SECURE','1')
    monkeypatch.setenv('PORTAL_SECRET','PROD_TEST_ONLY_SECRET_LONG_'*3)
    monkeypatch.setenv('PORTAL_ALLOWED_HOSTS','portal.example.bg')
    sys.modules.pop('portal',None)
    import portal
    with portal.SessionLocal() as db:
        staff=portal.User(username='staff',full_name='Staff',role='staff',active=True,
                          password_hash=portal.ph.hash('Secure_Staff_Password_56789'))
        db.add(staff);db.commit()
    with TestClient(portal.app,base_url='http://portal.example.bg') as client:
        assert client.get('/login').status_code == 400
    with TestClient(portal.app,base_url='https://portal.example.bg') as client:
        view=client.get('/login')
        assert view.status_code == 200
        assert view.headers['strict-transport-security'].startswith('max-age=')
        tok=re.search(r'name="login_token" value="([^"]+)"',view.text).group(1)
        r=client.post('/login',data={'username':'staff','password':'Secure_Staff_Password_56789',
                        'login_token':tok},follow_redirects=False)
        assert r.status_code==401
        assert client.cookies.get('portal_session') is None
    sys.modules.pop('portal',None)


def test_encrypted_backup_verification_restore_and_tamper(tmp_path, monkeypatch):
    from secure_backup import create_backup, verify_or_restore
    db_path=tmp_path/'private_data'/'portal.sqlite3';db_path.parent.mkdir()
    with sqlite3.connect(db_path) as db:
        db.execute('create table synthetic(id integer, value text)')
        db.execute('insert into synthetic values(1,?)',('synthetic only',))
    uploads=tmp_path/'private_data'/'uploads';uploads.mkdir()
    (uploads/'abcd.pdf').write_bytes(b'%PDF-1.4\nTEST DOCUMENT')
    monkeypatch.setenv('DATABASE_URL','sqlite:///'+str(db_path))
    monkeypatch.setenv('PRIVATE_STORAGE',str(uploads))
    backup=tmp_path/'encrypted.ppbk';password='Correct Horse Battery Staple Secret 16'
    assert create_backup(backup,password)==2
    assert verify_or_restore(backup,password)==2
    assert verify_or_restore(backup,password,tmp_path/'restored')==2
    assert (tmp_path/'restored'/'uploads'/'abcd.pdf').read_bytes()==b'%PDF-1.4\nTEST DOCUMENT'
    with pytest.raises(ValueError):
        verify_or_restore(backup,password,tmp_path/'restored')
    corrupted=tmp_path/'corrupted.ppbk';buffer=bytearray(backup.read_bytes());buffer[-32]^=1;corrupted.write_bytes(buffer)
    with pytest.raises(Exception):
        verify_or_restore(corrupted,password)
    with pytest.raises(Exception):
        verify_or_restore(backup,'This passphrase is definitely wrong')
    with pytest.raises(ValueError):
        create_backup(uploads/'bad.ppbk',password)


def test_old_patient_data_and_password_untouched_during_schema_upgrade(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_URL',f"sqlite:///{tmp_path / 'portal.sqlite3'}")
    monkeypatch.setenv('PRIVATE_STORAGE',str(tmp_path/'uploads'))
    monkeypatch.setenv('PORTAL_ENV','development')
    monkeypatch.setenv('PORTAL_ALLOWED_HOSTS','testserver')
    monkeypatch.setenv('PORTAL_SECRET','TEST_SECRET_NOT_FOR_PRODUCTION_'*2)
    # Set up old schema mimicking the relevant columns of v1.5.
    with sqlite3.connect(tmp_path/'portal.sqlite3') as db:
        db.execute('''CREATE TABLE users(id INTEGER PRIMARY KEY,username VARCHAR(80),full_name VARCHAR(160),password_hash VARCHAR(255),role VARCHAR(16),active BOOLEAN,must_change_password BOOLEAN,created_at DATETIME)''')
        db.execute('''CREATE TABLE reports(id INTEGER PRIMARY KEY,patient_id INTEGER,uploaded_by INTEGER,modality VARCHAR(20),title VARCHAR(120),exam_date DATE,stored_name VARCHAR(60),original_name VARCHAR(180),uploaded_at DATETIME,revoked_at DATETIME,published_at DATETIME,file_sha256 VARCHAR(64))''')
        db.execute('''CREATE TABLE audit(id INTEGER PRIMARY KEY,actor_id INTEGER,action VARCHAR(40),target_id INTEGER,occurred_at DATETIME,details VARCHAR(250))''')
        db.execute("INSERT INTO users(id, username, full_name, password_hash, role, active, must_change_password) VALUES(1,'9001010000','Test Patient','UNCHANGED_HASH','patient',1,0)")
    sys.modules.pop('portal',None)
    import portal
    with portal.SessionLocal() as db:
        u=db.get(portal.User,1)
        assert u.username=='9001010000' and u.password_hash=='UNCHANGED_HASH' and u.mfa_secret_enc is None
    with sqlite3.connect(tmp_path/'portal.sqlite3') as db:
        assert 'mfa_secret_enc' in [r[1] for r in db.execute('pragma table_info(users)')]
    sys.modules.pop('portal',None)


def test_session_created_before_staff_mfa_enrollment_is_revoked(setup_portal):
    portal, client, ids = setup_portal
    assert login(client,'admin-staff','STAFF_PASSWORD_GOOD_1234').status_code==303
    assert client.get('/dashboard').status_code==200
    token='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    with portal.SessionLocal() as db:
        staff=db.get(portal.User,ids['staff'])
        staff.mfa_secret_enc=portal.encrypt_mfa_secret(token)
        db.commit()
    r=client.get('/dashboard',follow_redirects=False)
    assert r.status_code==303 and r.headers['location']=='/login'

