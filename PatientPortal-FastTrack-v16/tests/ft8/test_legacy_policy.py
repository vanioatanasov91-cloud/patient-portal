"""Actual candidate HTTP routes + explicitly enabled synthetic AV policy."""
from datetime import timedelta
import hashlib
import importlib.util
from pathlib import Path
import sys

from fixtures import candidate, pdf_bytes, seed, ROOT
sys.path.insert(0, str(ROOT / 'app'))
from legacy_pdf_policy import install_synthetic_policy, attestations
from sqlalchemy import inspect, select, update
from fastapi.testclient import TestClient
sys.path.insert(0, str(ROOT / 'tests' / 'pdf'))
from test_clamd_scan_gate import FakeClamdSocket


def main():
    checks = 0
    def check(ok, label):
        nonlocal checks
        assert ok, label
        checks += 1
        print('PASS: ' + label)

    with candidate() as (p, root):
        payload = pdf_bytes()
        docid, sessions = seed(p, payload)
        check(p.pdf_av_policy is None and 'pdf_av_attestations_v1' not in inspect(p.engine).get_table_names(),
              'ordinary startup does not activate policy or create attestation schema')
        policy = install_synthetic_policy(p, root)
        real_connection = p.socket.create_connection
        p.PDF_SCAN_MODE = 'clamd'
        try:
            with TestClient(p.app, base_url='https://portal.example.test', follow_redirects=False) as c:
                def who(role):
                    c.cookies.clear()
                    c.cookies.set('portal_session', sessions[role][0])
                # Cookie name comes from backend, check below if renamed there.
                who('patient')
                for route in ('view', 'download'):
                    check(c.get(f'/reports/{docid}/{route}').status_code == 423,
                          'patient held without AV attestation: ' + route)
                who('other')
                check(c.get(f'/reports/{docid}/download').status_code == 404, 'other patient cannot discover report')
                check(c.post(f'/reports/{docid}/scan', data={'csrf':sessions['other'][1]}).status_code == 403,
                      'patient cannot scan/attest reports')
                who('staff')
                check(c.get(f'/reports/{docid}/preview').status_code == 423, 'unattested staff preview held too')
                page = c.get(f'/patients/{sessions["patient"][2]}')
                check(page.status_code == 200 and 'Провери с антивирус' in page.text, 'Bulgarian staff remediation visible')
                check(c.post(f'/reports/{docid}/scan', data={'csrf':'invalid'}).status_code == 403, 'rescan requires CSRF')
                with p.SessionLocal() as db:
                    doc = db.get(p.Report, docid)
                    published = doc.published_at
                    doc.published_at = None; db.commit()
                    p.log(db, sessions['staff'][2], 'report_previewed', docid,
                          details='sha256:' + hashlib.sha256(payload).hexdigest()); db.commit()
                check(c.post(f'/reports/{docid}/publish', data={'csrf':sessions['staff'][1], 'confirm_owner':'yes'}).status_code == 423,
                      'checksum and historic preview alone cannot authorize publishing')
                def scan(reply=None, offline=False, mutate=None):
                    def connect(*a, **k):
                        if offline: raise ConnectionRefusedError('SYNTHETIC_ONLY')
                        return FakeClamdSocket(reply, mutate)
                    p.socket.create_connection = connect
                    return c.post(f'/reports/{docid}/scan', data={'csrf':sessions['staff'][1]})
                check(scan(offline=True).status_code == 503, 'daemon outage leaves hold')
                check(scan(b'stream: Eicar-Test-Signature FOUND\0').status_code == 422, 'malware remains held')
                check(scan(b'stream: OK\0').status_code == 303, 'clean mocked scan records attestation')
                check(c.get(f'/reports/{docid}/preview').content == payload, 'clean exact snapshot can be previewed')
                check(c.post(f'/reports/{docid}/publish', data={'csrf':sessions['staff'][1], 'confirm_owner':'yes'}).status_code == 303,
                      'existing preview/publish workflow preserved after attestation')
                who('patient')
                check(c.get(f'/reports/{docid}/download').content == payload, 'authorized patient receives exact attested bytes')
                who('staff')
                check(scan(offline=True).status_code == 503, 'failed rescan invalidates previous clean result')
                check(c.get(f'/reports/{docid}/preview').status_code == 423, 'older clean cannot bypass latest hold')
                p.PDF_SCAN_MODE = 'off'
                check(scan(b'stream: OK\0').status_code == 503, 'scanner-off never creates clean attestation')
                p.PDF_SCAN_MODE = 'clamd'
                check(scan(b'stream: OK\0', mutate=lambda: (p.STORAGE / 'synthetic.pdf').write_bytes(payload + b' ')).status_code == 409,
                      'stored file mutation during rescan cannot create clean attestation')
                (p.STORAGE / 'synthetic.pdf').write_bytes(payload)
                check(c.get(f'/reports/{docid}/preview').status_code == 423, 'failed scan remains held even after original bytes restored')
                check(scan(b'stream: OK\0').status_code == 303, 'explicit clean rescan recovers hold')
                with p.SessionLocal() as db:
                    # Model the pre-v6 un-hashed published legacy fixture explicitly.
                    db.get(p.Report, docid).file_sha256 = None; db.commit()
                (p.STORAGE / 'synthetic.pdf').write_bytes(payload + b' ')
                check(c.get(f'/reports/{docid}/preview').status_code == 423, 'legacy file without stored checksum still binds attestation bytes')
                (p.STORAGE / 'synthetic.pdf').write_bytes(payload)
                with p.SessionLocal() as db:
                    row = db.execute(select(attestations).order_by(attestations.c.id.desc())).mappings().first()
                    check(row['verdict'] == 'clean' and row['schema_version'] == 1 and row['source'] == 'clamd-instream-v1'
                          and row['sha256'] == hashlib.sha256(payload).hexdigest(), 'durable version/verdict/source/time/hash recorded')
                    check(db.get(p.Report, docid).revoked_at is None, 'no automatic revocation/deletion')
                    db.execute(update(attestations).where(attestations.c.id == row['id']).values(
                        scanned_at_utc=(p.now() + timedelta(days=1)).isoformat())); db.commit()
                check(c.get(f'/reports/{docid}/preview').status_code == 423, 'future attestation rejected')
                # Upload with scanner off stays held; no implicit AV upgrade.
                p.PDF_SCAN_MODE = 'off'
                new = pdf_bytes('SYNTHETIC NEW UPLOAD')
                check(c.post(f'/patients/{sessions["patient"][2]}/reports',
                      files={'file':('synthetic-new.pdf', new, 'application/pdf')},
                      data={'csrf':sessions['staff'][1], 'title':'Синтетичен нов PDF', 'modality':'ЯМР',
                            'exam_date':'2020-01-01','confirm_owner':'yes'}).status_code == 303, 'development upload workflow preserved')
                with p.SessionLocal() as db:
                    new_doc = db.scalar(select(p.Report).order_by(p.Report.id.desc()))
                check(c.get(f'/reports/{new_doc.id}/preview').status_code == 423, 'unscanned development upload held')
                p.PDF_SCAN_MODE = 'clamd'
                p.socket.create_connection = lambda *a, **k: FakeClamdSocket(b'stream: OK\0')
                scanned = pdf_bytes('SYNTHETIC CLEAN UPLOAD')
                check(c.post(f'/patients/{sessions["patient"][2]}/reports',
                      files={'file':('synthetic-clean.pdf', scanned, 'application/pdf')},
                      data={'csrf':sessions['staff'][1], 'title':'Синтетичен проверен PDF', 'modality':'ЯМР',
                            'exam_date':'2020-01-01','confirm_owner':'yes'}).status_code == 303, 'mock-scanned upload accepted')
                with p.SessionLocal() as db:
                    clean_doc = db.scalar(select(p.Report).order_by(p.Report.id.desc()))
                check(c.get(f'/reports/{clean_doc.id}/preview').content == scanned, 'mock-scanned upload carries durable attestation immediately')
                with p.SessionLocal() as db:
                    pending = policy.add_result(db, clean_doc.id, clean_doc.file_sha256, 'pending')
                    newer = policy.add_result(db, clean_doc.id, clean_doc.file_sha256, 'pending')
                    # An earlier concurrent scan completes after the newer hold.
                    db.execute(update(attestations).where(attestations.c.id == pending).values(verdict='clean'))
                    db.commit()
                check(c.get(f'/reports/{clean_doc.id}/preview').status_code == 423, 'out-of-order scan completion cannot overwrite a newer hold')
                with p.SessionLocal() as db:
                    db.execute(update(attestations).where(attestations.c.id == newer).values(verdict='clean'))
                    db.commit()
                check(c.get(f'/reports/{clean_doc.id}/preview').content == scanned, 'latest clean completion restores access')
                # Activation guard never creates schema outside confirmed synthetic root.
                try: install_synthetic_policy(p, Path('/workspace'))
                except RuntimeError: check(True, 'fixture-only migration guard rejects non-synthetic path')
                else: raise AssertionError('unsafe activation')
        finally:
            p.socket.create_connection = real_connection
    print(f'PASS: FT8 LEGACY POLICY ({checks} checks). HOLD / NO-GO; MOCKED SCANNER ONLY.')


if __name__ == '__main__': main()
