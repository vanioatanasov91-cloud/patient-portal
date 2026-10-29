"""FT7 synthetic read-only legacy inventory regression. No patient data or real AV."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'tools' / 'legacy_pdf_inventory.py'


def fake_pdf(value: bytes) -> bytes:
    return b'%PDF-1.4\n' + value + b'\nstartxref\n0\n%%EOF\n'


def main() -> None:
    checks = 0
    def check(value, desc):
        nonlocal checks
        if not value:
            raise AssertionError(desc)
        checks += 1
        print('PASS: ' + desc)

    with tempfile.TemporaryDirectory(prefix='FT7_OFFLINE_PDF_INVENTORY_') as work:
        tmp = Path(work)
        uploads = tmp/'uploads'; uploads.mkdir()
        db = tmp/'offline-copy.sqlite3'
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE reports (stored_name TEXT, file_sha256 TEXT, published_at TEXT, revoked_at TEXT)')
            def add(name, expected, published=None, revoked=None):
                conn.execute('INSERT INTO reports VALUES (?, ?, ?, ?)',(name,expected,published,revoked))
            good=fake_pdf(b'SYNTHETIC SAFE CONTAINER NOT AN ANTIVIRUS TEST')
            (uploads/'good.pdf').write_bytes(good)
            add('good.pdf',hashlib.sha256(good).hexdigest(),'2020-01-01')
            (uploads/'legacy.pdf').write_bytes(good)
            add('legacy.pdf',None,'2020-01-01')
            (uploads/'tamper.pdf').write_bytes(good)
            add('tamper.pdf','a'*64,'2020-01-01')
            add('missing.pdf',hashlib.sha256(good).hexdigest(),'2020-01-01')
            add('../escape.pdf',None,'2020-01-01')
            (uploads/'invalid.pdf').write_bytes(b'%PDF-1.4\nCORRUPTED_WITHOUT_ANY_VALID_TRAILER')
            add('invalid.pdf',None)
            (uploads/'badhex.pdf').write_bytes(good)
            add('badhex.pdf','xyz')
            (uploads/'revoked.pdf').write_bytes(good)
            add('revoked.pdf',hashlib.sha256(good).hexdigest(),None,'2020-01-02')
            conn.commit()
        before=db.read_bytes()
        args=[sys.executable,'-B',str(SCRIPT),'--db-file',str(db),'--storage-dir',str(uploads)]
        refused=subprocess.run(args,capture_output=True,text=True,timeout=10)
        check(refused.returncode != 0 and 'usage:' in refused.stderr,
              'explicit offline-copy confirmation required')
        result=subprocess.run(args+['--confirm-offline-copy'],capture_output=True,text=True,timeout=10)
        check(result.returncode == 0,'offline inventory completes')
        report=json.loads(result.stdout)
        check(report['documents_total']==8,'all eight artificial DB rows inventoried')
        check(report['sha256_matches']==2 and report['missing_stored_sha256']==1,
              'matching and legacy missing hashes reported separately')
        check(report['stored_sha256_mismatch']==1 and report['invalid_stored_sha256']==1,
              'mismatched and malformed hashes reported')
        check(report['missing_or_symlink_file']==1 and report['unsafe_stored_name']==1,
              'missing and traversal paths rejected')
        check(report['invalid_pdf_container']==1 and report['bounded_container_checked']==5,
              'invalid container rejected without confusing with malware verdict')
        check(report['published_active']==5 and report['revoked']==1,
              'published and revoked counts are separate')
        check(report['av_attestation_unknown']==8 and report['requires_independent_av_review'],
              'no legacy document is misrepresented as antivirus-cleared')
        check(report['malware_scanned'] is False and report['data_mutated'] is False,
              'report accurately declares read-only and no antivirus scan')
        check(db.read_bytes()==before,'offline SQLite DB unchanged')
        check('good.pdf' not in result.stdout and 'SYNTHETIC' not in result.stdout,
              'report contains no filenames or document content')
        try:
            (uploads/'symlink.pdf').symlink_to(uploads/'good.pdf')
        except (OSError, NotImplementedError):
            print('SKIP: symlink creation not authorized on this Windows machine')
        else:
            with sqlite3.connect(db) as conn:
                conn.execute('INSERT INTO reports VALUES (?,?,?,?)',('symlink.pdf',None,None,None))
                conn.commit()
            result2=subprocess.run(args+['--confirm-offline-copy'],capture_output=True,text=True,timeout=10)
            check(json.loads(result2.stdout)['missing_or_symlink_file']==2,
                  'symbolic-link PDFs never dereferenced')
        check(json.loads(result.stdout)['release_gate']=='HOLD / NO-GO',
              'all inventory results preserve release hold')
    print(f'PASS: FAST TRACK 7 OFFLINE INVENTORY ({checks} checks)')


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('FAIL/HOLD: FT7 inventory regression ' + type(exc).__name__,file=sys.stderr)
        raise SystemExit(1)
