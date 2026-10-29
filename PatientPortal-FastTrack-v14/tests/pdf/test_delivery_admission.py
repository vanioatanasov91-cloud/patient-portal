"""Fast Track 5: fake-only PDF delivery admission and slot lifecycle tests.

All input, storage, account names and DB values are synthetic in temp dir.
Never contacts installed services or reads private patient files.
"""
from __future__ import annotations

import asyncio
import gc
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
    from sqlalchemy import select, func
    env_before = os.environ.copy()
    name = "ft5_pdf_delivery_admission_fake_only"
    candidate = None
    n = 0
    def passed(cond, desc):
        nonlocal n
        if not cond:
            raise AssertionError(desc)
        n += 1
        print("PASS: " + desc, flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix="FT5_ADMISSION_FAKE_") as temp:
            root = Path(temp)
            appdir = root / "app"; appdir.mkdir()
            safe_copy(appdir)
            uploads = root / "fake_uploads"; uploads.mkdir()
            dbfile = root / "fake.sqlite3"
            os.environ.update({
                "PORTAL_ENV": "development",
                "PORTAL_SECRET": secrets.token_urlsafe(48),
                "PORTAL_COOKIE_SECURE": "1",
                "PORTAL_ALLOWED_HOSTS": "portal.example.test",
                "DATABASE_URL": "sqlite:///" + dbfile.as_posix(),
                "PRIVATE_STORAGE": str(uploads),
                "PORTAL_MAX_ACTIVE_PDF_DELIVERIES": "2",
            })
            spec = importlib.util.spec_from_file_location(name, appdir / "portal.py")
            assert spec and spec.loader
            candidate = importlib.util.module_from_spec(spec)
            sys.modules[name] = candidate
            spec.loader.exec_module(candidate)
            try:
                passed(candidate.MAX_ACTIVE_PDF_DELIVERIES == 2, "per-process PDF response admission limit configured")
                def slots_free():
                    slots = []
                    try:
                        for _ in range(candidate.MAX_ACTIVE_PDF_DELIVERIES + 1):
                            if candidate._pdf_delivery_slots.acquire(blocking=False):
                                slots.append(1)
                            else:
                                break
                        return len(slots)
                    finally:
                        for _ in slots:
                            candidate._pdf_delivery_slots.release()
                passed(slots_free() == 2, "all delivery slots initially free")
                pw = secrets.token_urlsafe(24)
                with candidate.SessionLocal() as db:
                    staff = candidate.User(username="FT5_FAKE_STAFF", full_name="SYNTHETIC STAFF",
                        role="staff", active=True, password_hash=candidate.ph.hash(pw))
                    patient = candidate.User(username="FT5_FAKE_PATIENT", full_name="SYNTHETIC PATIENT",
                        role="patient", active=True,
                        password_hash=candidate.ph.hash(secrets.token_urlsafe(24)))
                    db.add_all([staff, patient]); db.commit()
                    sid, pid = staff.id, patient.id
                buf = io.BytesIO()
                c = canvas.Canvas(buf)
                c.drawString(45, 725, "FAKE DOCUMENT - NEVER REAL PATIENT DATA")
                c.save()
                payload = buf.getvalue()
                with TestClient(candidate.app, base_url="https://portal.example.test",
                                follow_redirects=False) as client:
                    token = client.get('/login').cookies.get('login_csrf')
                    login = client.post('/login', data={'username': 'FT5_FAKE_STAFF',
                        'password': pw, 'login_token': token}, follow_redirects=False)
                    passed(login.status_code == 303, 'synthetic staff session authenticated')
                    with candidate.SessionLocal() as db:
                        csrf = db.scalar(select(candidate.LoginSession).where(
                            candidate.LoginSession.user_id == sid)).csrf_token
                    response = client.post(f'/patients/{pid}/reports',
                        files={'file':('fake.pdf', payload, 'application/pdf')},
                        data={'title':'SYNTHETIC','modality':'ЯМР',
                              'exam_date':'2020-01-01', 'confirm_owner':'yes', 'csrf':csrf},
                        follow_redirects=False)
                    passed(response.status_code == 303, 'synthetic draft uploaded')
                    with candidate.SessionLocal() as db:
                        doc = db.scalar(select(candidate.Report).where(candidate.Report.patient_id == pid))
                        docid = doc.id
                        pdfpath = uploads / doc.stored_name
                        audits_before = db.scalar(select(func.count(candidate.Audit.id)))
                    for _ in range(2):
                        assert candidate._pdf_delivery_slots.acquire(blocking=False)
                    try:
                        response = client.get(f'/reports/{docid}/preview')
                        passed(response.status_code == 503, 'at-limit HTTP PDF preview rejected fail-fast')
                        passed(response.headers.get('retry-after') == '2', 'at-limit response includes retry header')
                        passed('no-store' in response.headers.get('cache-control',''),
                               'at-limit response disables caching')
                        with candidate.SessionLocal() as db:
                            passed(db.scalar(select(func.count(candidate.Audit.id))) == audits_before,
                                   'rejected admission does not create PDF preview audit')
                    finally:
                        candidate._pdf_delivery_slots.release()
                        candidate._pdf_delivery_slots.release()
                    passed(slots_free() == 2, 'slots released after saturation fixture')
                    response = client.get(f'/reports/{docid}/preview')
                    passed(response.status_code == 200 and response.content == payload,
                           'normal preview serves original verified bytes')
                    passed(slots_free() == 2, 'successful HTTP response releases delivery slot')
                    pdfpath.write_bytes(payload + b'INVALID TAMPER')
                    response = client.get(f'/reports/{docid}/preview')
                    passed(response.status_code == 409, 'tampered PDF rejected')
                    passed(slots_free() == 2, 'failed PDF integrity verification releases slot')
                    pdfpath.write_bytes(payload)
                    response = client.post(f'/reports/{docid}/publish',
                        data={'csrf':csrf,'confirm_owner':'yes'}, follow_redirects=False)
                    passed(response.status_code == 303, 'synthetic draft published after preview')
                    response = client.get(f'/reports/{docid}/download')
                    passed(response.status_code == 200 and response.content == payload,
                           'published PDF downloads exact verified bytes')
                    passed(slots_free() == 2, 'download response releases slot')
                    # ASGI send exception emulates disconnected/cancelled response.
                    assert candidate._pdf_delivery_slots.acquire(blocking=False)
                    r = candidate.pdf_snapshot_response(payload, docid, inline=True)
                    async def fail_send(_message):
                        raise RuntimeError('SIMULATED_FAKE_DISCONNECT')
                    async def unused_receive():
                        return {'type':'http.request','body':b'','more_body':False}
                    try:
                        asyncio.run(r({'type':'http','method':'GET','path':'/synthetic',
                                       'headers':[]}, unused_receive, fail_send))
                    except RuntimeError as exc:
                        passed(str(exc) == 'SIMULATED_FAKE_DISCONNECT',
                               'synthetic client disconnect propagated')
                    else:
                        raise AssertionError('synthetic disconnect unexpectedly delivered')
                    passed(slots_free() == 2, 'ASGI send failure releases slot')
                    # Audit commit error before response construction must release slot.
                    old_log = candidate.log
                    def raise_audit(*args, **kwargs):
                        raise RuntimeError('SYNTHETIC_AUDIT_FAILURE')
                    candidate.log = raise_audit
                    try:
                        try:
                            client.get(f'/reports/{docid}/download')
                        except RuntimeError as exc:
                            passed(str(exc) == 'SYNTHETIC_AUDIT_FAILURE',
                                   'synthetic audit failure propagated')
                        else:
                            raise AssertionError('synthetic audit failure hidden')
                    finally:
                        candidate.log = old_log
                    passed(slots_free() == 2, 'pre-response audit exception releases slot')
            finally:
                candidate.engine.dispose()
                sys.modules.pop(name, None)
                candidate = None
                gc.collect()
        print(f'PASS: FAST TRACK 5 PDF ADMISSION COMPLETE ({n} checks)')
        print('RELEASE GATE: HOLD / NO-GO. PER-WORKER LIMIT ONLY; NO LOAD TEST.')
    finally:
        os.environ.clear(); os.environ.update(env_before)


if __name__ == '__main__':
    try:
        run()
    except Exception as exc:
        print('FAIL/HOLD: Fast Track 5 synthetic PDF admission: ' +
              type(exc).__name__ + ' (details withheld)', file=sys.stderr)
        print('RELEASE GATE: HOLD / NO-GO.', file=sys.stderr)
        sys.exit(1)
