"""AV hold policy with explicit table binding; no automatic production activation.

No import-time DDL, no backfill, no automatic revocation or production activation.
The monotonic scan-attempt order prevents an older scan from overriding a newer hold.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile

from fastapi import HTTPException
from sqlalchemy import Column, Integer, MetaData, String, Table, insert, select, update

metadata = MetaData()
attestations = Table(
    'pdf_av_attestations_v1', metadata,
    Column('id', Integer, primary_key=True),
    Column('report_id', Integer, nullable=False, index=True),
    Column('schema_version', Integer, nullable=False),
    Column('sha256', String(64), nullable=False),
    Column('verdict', String(16), nullable=False),
    Column('source', String(40), nullable=False),
    Column('scanned_at_utc', String(40), nullable=False),
)
HOLD_MESSAGE = 'PDF документът е задържан до проверка за сигурност. Свържете се с регистратурата.'


class AvPolicy:
    def __init__(self, root: Path, *, table=attestations):
        self.root = root
        self.table = table

    def add_result(self, db, report_id, checksum, verdict, source='clamd-instream-v1'):
        result = db.execute(insert(self.table).values(
            report_id=report_id, schema_version=1, sha256=checksum,
            verdict=verdict, source=source,
            scanned_at_utc=datetime.now(timezone.utc).isoformat()))
        return result.inserted_primary_key[0]

    def require(self, db, report_id, checksum):
        row = db.execute(select(self.table).where(
            self.table.c.report_id == report_id).order_by(self.table.c.id.desc()).limit(1)).mappings().first()
        valid = False
        if row:
            try:
                scanned = datetime.fromisoformat(row['scanned_at_utc'])
                valid = (row['schema_version'] == 1 and row['verdict'] == 'clean'
                         and row['source'] == 'clamd-instream-v1'
                         and row['sha256'] == checksum
                         and scanned.tzinfo is not None
                         and scanned <= datetime.now(timezone.utc))
            except (TypeError, ValueError):
                pass
        if not valid:
            raise HTTPException(423, HOLD_MESSAGE, headers={'Cache-Control': 'no-store'})

    def scan_existing(self, portal, db, doc, actor_id):
        # Reuse the existing bounded snapshot admission while taking/scanning bytes.
        if not portal._pdf_delivery_slots.acquire(blocking=False):
            raise HTTPException(503, 'Временно ограничение на PDF проверките.', headers={'Retry-After': '2'})
        try:
            payload, checksum = portal.snapshot_verified_pdf(doc)
            # Commit a hold BEFORE contacting the daemon; failures never retain
            # an earlier clean attestation. Do not alter Report lifecycle fields.
            event = self.add_result(db, doc.id, checksum, 'pending')
            db.commit()
            verdict = 'error'
            try:
                if len(payload) > portal.MAX_PDF:
                    raise HTTPException(413, 'PDF над 15 MB изисква отделна одобрена процедура.')
                with tempfile.TemporaryDirectory(prefix='scan_', dir=self.root) as folder:
                    path = Path(folder) / 'synthetic.pdf'
                    path.write_bytes(payload)
                    path.chmod(0o600)
                    clean = portal.scan_pdf_for_malware(path)
                    portal.assert_pdf_unchanged_after_scan(path, checksum)
                if clean is not True:
                    raise HTTPException(503, 'Изключен скенер не може да удостовери PDF.')
                # Check the current stored snapshot again. Delivery also checks
                # its own exact bytes, so later tampering cannot reuse this event.
                _, current = portal.snapshot_verified_pdf(doc)
                if current != checksum:
                    raise HTTPException(409, 'PDF документът се е променил по време на проверката.')
                verdict = 'clean'
            except HTTPException as exc:
                verdict = 'infected' if exc.status_code == 422 else 'error'
                raise
            finally:
                db.execute(update(self.table).where(self.table.c.id == event).values(
                    verdict=verdict, scanned_at_utc=datetime.now(timezone.utc).isoformat()))
                portal.log(db, actor_id, 'report_av_checked', doc.id, details='AV: ' + verdict)
                db.commit()
        finally:
            portal._pdf_delivery_slots.release()


# Compatibility alias: the original fixture installer and all v8/v9 tests remain.
SyntheticAvPolicy = AvPolicy


def install_synthetic_policy(portal, root: Path):
    """Explicit fixture-only schema creation. NEVER a production migration API."""
    root = root.resolve()
    dbpath = Path(portal.engine.url.database or '').resolve()
    if (portal.PROD or portal.ENV != 'development' or portal.engine.dialect.name != 'sqlite'
            or not root.is_relative_to(Path(tempfile.gettempdir()).resolve())
            or not root.name.startswith('FT8_SYNTHETIC_')
            or not dbpath.is_relative_to(root) or not portal.STORAGE.is_relative_to(root)
            or not (root / 'SYNTHETIC_ONLY').is_file()):
        raise RuntimeError('HOLD: AV policy schema may only be prepared in an explicit temporary synthetic fixture')
    # Only called on freshly generated synthetic DBs by the tests/harness.
    metadata.create_all(portal.engine)
    policy = SyntheticAvPolicy(root)
    portal.pdf_av_policy = policy
    return policy
