"""Only generated patients, PDFs, credentials and ephemeral SQLite, never live data."""
from contextlib import contextmanager
from datetime import date
import importlib.util
import io
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests' / 'pdf'))
from test_pdf_hardening import safe_copy


@contextmanager
def candidate():
    before = os.environ.copy()
    module_name = 'ft8_synthetic_backend'
    portal = None
    with tempfile.TemporaryDirectory(prefix='FT8_SYNTHETIC_') as folder:
        root = Path(folder)
        (root / 'SYNTHETIC_ONLY').touch()
        appdir = root / 'app'; appdir.mkdir()
        safe_copy(appdir)
        shutil.copyfile(ROOT / 'app' / 'legacy_pdf_policy.py', appdir / 'legacy_pdf_policy.py')
        os.environ.update(PORTAL_ENV='development', PORTAL_SECRET=secrets.token_urlsafe(48),
                          PORTAL_COOKIE_SECURE='1', PORTAL_ALLOWED_HOSTS='portal.example.test,127.0.0.1',
                          DATABASE_URL='sqlite:///' + (root / 'synthetic.sqlite3').as_posix(),
                          PRIVATE_STORAGE=str(root / 'uploads'), PORTAL_PDF_SCAN_MODE='off')
        try:
            spec = importlib.util.spec_from_file_location(module_name, appdir / 'portal.py')
            portal = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = portal
            spec.loader.exec_module(portal)
            yield portal, root
        finally:
            if portal is not None:
                portal.engine.dispose()
            sys.modules.pop(module_name, None)
            os.environ.clear(); os.environ.update(before)


def pdf_bytes(label='SYNTHETIC FT8', *, compress=True):
    from reportlab.pdfgen import canvas
    data = io.BytesIO(); pdf = canvas.Canvas(data, pageCompression=int(compress))
    pdf.drawString(60, 700, label); pdf.save()
    return data.getvalue()


def seed(portal, payload):
    with portal.SessionLocal() as db:
        staff = portal.User(username='SYNTHETIC_STAFF', full_name='Синтетичен служител', role='staff',
                            password_hash='NOT_A_REAL_LOGIN', active=True)
        patient = portal.User(username='SYNTHETIC_PATIENT', full_name='Синтетичен пациент', role='patient',
                              password_hash='NOT_A_REAL_LOGIN', active=True)
        other = portal.User(username='SYNTHETIC_OTHER', full_name='Друг тестов пациент', role='patient',
                            password_hash='NOT_A_REAL_LOGIN', active=True)
        db.add_all([staff, patient, other]); db.flush()
        doc = portal.Report(patient_id=patient.id, uploaded_by=staff.id, modality='ЯМР',
                            title='СИНТЕТИЧЕН ДОКУМЕНТ', exam_date=date(2020, 1, 1),
                            stored_name='synthetic.pdf', original_name='synthetic.pdf',
                            published_at=portal.now(), file_sha256=None)
        db.add(doc); db.flush()
        (portal.STORAGE / doc.stored_name).write_bytes(payload)
        sessions = {}
        for role, user in [('staff', staff), ('patient', patient), ('other', other)]:
            token, csrf = portal.make_session(db, user)
            sessions[role] = (token, csrf, user.id)
        db.commit()
        return doc.id, sessions
