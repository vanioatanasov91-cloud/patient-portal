"""Stage 6.12: generate artificial SQLite + PDFs and test a SYNTHETIC-ONLY backup helper.
NO patient data, production database, real archive, real private storage, live services, or sockets.
"""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing

from reportlab.pdfgen import canvas

SELF = Path(__file__).resolve().parent
HELPER = SELF / 'stage612_backup_helper_FAKE_ONLY.py'
EXPECTED_SHA = 'f2804a1fecdd1d4aaa330a7ac83710ff333bc12c371fc49f9ec95fd4321bddc3'


def must(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fh:
        while True:
            part = fh.read(1024 * 1024)
            if not part:
                return h.hexdigest()
            h.update(part)


def run():
    must(sha(HELPER) == EXPECTED_SHA, 'Synthetic-only helper SHA mismatch')
    print('PASS: Synthetic-only DR helper SHA-256 pinned')
    # A newly created private temp workspace; no existing local patient files.
    with tempfile.TemporaryDirectory(prefix='stage612_FAKE_ONLY_') as folder:
        root = Path(folder)
        app = root / 'fake_app'
        private = app / 'private_data'
        uploads = private / 'uploads'
        uploads.mkdir(parents=True)
        db = private / 'portal.sqlite3'
        with closing(sqlite3.connect(db)) as con:
            con.execute('CREATE TABLE patients (patient_code TEXT PRIMARY KEY, label TEXT NOT NULL)')
            con.executemany('INSERT INTO patients VALUES (?,?)', [
                ('TEST0001', 'FICTIONAL PATIENT A'),
                ('TEST0002', 'FICTIONAL PATIENT B'),
            ])
            con.commit()
        for i in range(2):
            pdf = uploads / f'synthetic_doc_{i + 1}.pdf'
            c = canvas.Canvas(str(pdf))
            c.drawString(45, 750, 'SYNTHETIC TEST DOCUMENT - NO PATIENT DATA')
            c.drawString(45, 725, f'Example file {i+1} - FAKE ONLY')
            c.save()

        os.environ['DATABASE_URL'] = f'sqlite:///{db}'
        os.environ['PRIVATE_STORAGE'] = str(uploads)
        # Even if a .env exists in the user's current working folder, the helper is imported
        # from a new blank directory (not the installed portal).
        helper_copy = root / HELPER.name
        shutil.copyfile(HELPER, helper_copy)
        spec = importlib.util.spec_from_file_location('stage612_fake_backup_only', helper_copy)
        must(spec is not None and spec.loader is not None, 'Cannot load synthetic helper')
        backup_tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(backup_tool)

        outbox = root / 'fake_offhost'
        outbox.mkdir()
        backup = outbox / 'synthetic_ONLY.ppbk'
        secret = secrets.token_urlsafe(40)  # never print or persist passphrase
        count = backup_tool.create_backup(backup, secret)
        must(count == 3, 'Unexpected fake source file count')
        print('PASS: 3 synthetic files encrypted to temporary .ppbk')
        verified = backup_tool.verify_or_restore(backup, secret)
        must(verified == 3, 'Synthetic authenticated verification failed')
        print('PASS: AES-GCM authentication + manifest hashes verified')

        copied = root / 'offline_copy.ppbk'
        shutil.copyfile(backup, copied)
        must(sha(backup) == sha(copied), 'Synthetic copy checksum mismatch')
        print('PASS: Synthetic archive copy SHA-256 matches')

        destination = root / 'recovery' / 'restored_fresh'
        restored_count = backup_tool.verify_or_restore(copied, secret, destination)
        must(restored_count == 3, 'Restored fake file count wrong')
        must(destination.is_dir(), 'Fresh destination missing')
        must(sorted(p.name for p in (destination/'uploads').iterdir()) == ['synthetic_doc_1.pdf','synthetic_doc_2.pdf'], 'Fake PDF files missing')
        with closing(sqlite3.connect(f'file:{(destination / "portal.sqlite3").as_posix()}?mode=ro', uri=True)) as con:
            integrity = con.execute('PRAGMA integrity_check').fetchone()[0]
            rows = con.execute('SELECT COUNT(*) FROM patients').fetchone()[0]
        must(integrity == 'ok' and rows == 2, 'Fake SQLite integrity / rows failed')
        for i in range(2):
            src = uploads / f'synthetic_doc_{i+1}.pdf'
            recovered = destination / 'uploads' / f'synthetic_doc_{i+1}.pdf'
            must(sha(src) == sha(recovered), 'Fake PDF content mismatch')
            with recovered.open('rb') as fh:
                must(fh.read(5) == b'%PDF-', 'Fake PDF header missing')
        print('PASS: RESTORE to NEW temporary directory (2 PDF + 1 SQLite)')
        print('PASS: SQLite integrity=ok; fake rows=2; PDF hashes/headers match')

        refused = False
        try:
            backup_tool.verify_or_restore(copied, secret, destination)
        except ValueError:
            refused = True
        must(refused, 'Restoring onto existing directory was not refused')
        print('PASS: Existing destination cannot be overwritten')

        corrupt = root / 'TAMPERED_FAKE_ONLY.ppbk'
        data = bytearray(copied.read_bytes())
        data[len(data)//2] ^= 1
        corrupt.write_bytes(data)
        rejected = False
        try:
            backup_tool.verify_or_restore(corrupt, secret)
        except Exception:
            rejected = True
        must(rejected, 'Tampered fake archive was not rejected')
        print('PASS: Synthetic tamper detected and rejected')
        del backup_tool
    print('PASS: STAGE6.12 SYNTHETIC DR REHEARSAL COMPLETE')
    print('NO REAL BACKUPS / PATIENT DATA / WINDOWS SERVICES ACCESSED')
    print('RELEASE GATE: HOLD / NO-GO. Independent off-host restore remains required.')

if __name__ == '__main__':
    try:
        run()
    except Exception as exc:
        print(f'FAIL: STAGE6.12 SYNTHETIC DR CHECK: {type(exc).__name__}: {exc}', file=sys.stderr)
        print('RELEASE GATE: HOLD / NO-GO', file=sys.stderr)
        sys.exit(1)
