#!/usr/bin/env python3
"""FT7 offline/READ-ONLY PDF inventory. Never scans for malware or changes records.

Accepts only an operator-confirmed, closed/offline SQLite + upload-folder COPY.
Prints aggregates only: no patient names, filenames, hashes, or PDF content.
This is an INVENTORY tool, NOT an AV attestation or a deployment migration.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_LEGACY_PDF = 64 * 1024 * 1024
FILE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}\Z")
DIGEST_PATTERN = re.compile(r"[a-fA-F0-9]{64}\Z")
TRAILER_PATTERN = re.compile(rb"startxref[ \t\r\n]+[0-9]+[ \t\r\n]+%%EOF[ \t\r\n]*\Z")


def _forbidden_live_candidate(path: Path) -> bool:
    # Never operate directly on any potential live database inside the bundled app.
    return path == ROOT / 'app' or (ROOT / 'app') in path.parents


def summarize(db_file: Path, storage_dir: Path) -> dict:
    """Read metadata + bounded bytes, return only anonymous aggregate counters."""
    if (db_file.is_symlink() or storage_dir.is_symlink()
            or not db_file.is_file() or not storage_dir.is_dir()):
        raise ValueError('An offline database FILE and storage DIRECTORY are required')
    db_file = db_file.resolve(strict=True)
    storage_dir = storage_dir.resolve(strict=True)
    if _forbidden_live_candidate(db_file) or _forbidden_live_candidate(storage_dir):
        raise ValueError('Refused to use the bundled application data directory')
    counters: Counter[str] = Counter()
    # sqlite mode=ro refuses creating/modifying the DB; the caller MUST use a
    # closed offline copy (a live WAL DB is not a consistent backup).
    uri = db_file.as_uri() + '?mode=ro'
    with sqlite3.connect(uri, uri=True, timeout=1) as conn:
        conn.execute('PRAGMA query_only=ON')
        conn.execute('PRAGMA busy_timeout=1000')
        rows = conn.execute('SELECT stored_name, file_sha256, published_at, revoked_at FROM reports')
        for name, expected_hash, published_at, revoked_at in rows:
            counters['documents_total'] += 1
            if counters['documents_total'] > 100000:
                raise ValueError('Offline inventory safety limit exceeded')
            if published_at is not None and revoked_at is None:
                counters['published_active'] += 1
            if revoked_at is not None:
                counters['revoked'] += 1
            # Fast Track 6 stores no durable AV attestation for legacy or new files.
            counters['av_attestation_unknown'] += 1
            if not isinstance(name, str) or not FILE_PATTERN.fullmatch(name):
                counters['unsafe_stored_name'] += 1
                continue
            path = storage_dir / name
            if path.is_symlink() or not path.is_file():
                counters['missing_or_symlink_file'] += 1
                continue
            if not path.resolve().is_relative_to(storage_dir):
                counters['unsafe_stored_name'] += 1
                continue
            size = path.stat().st_size
            if size < 20 or size > MAX_LEGACY_PDF:
                counters['out_of_bounds_size'] += 1
                continue
            digest = hashlib.sha256()
            with path.open('rb') as source:
                magic = source.read(5)
                digest.update(magic)
                tail = bytearray()
                read_total = len(magic)
                while chunk := source.read(1024 * 1024):
                    read_total += len(chunk)
                    if read_total > MAX_LEGACY_PDF:
                        break
                    digest.update(chunk)
                    tail.extend(chunk)
                    if len(tail) > 4096:
                        del tail[:-4096]
            if read_total != size or read_total > MAX_LEGACY_PDF:
                counters['out_of_bounds_size'] += 1
                continue
            if magic != b'%PDF-' or not TRAILER_PATTERN.search(bytes(tail)):
                counters['invalid_pdf_container'] += 1
                continue
            counters['bounded_container_checked'] += 1
            if expected_hash is None:
                counters['missing_stored_sha256'] += 1
            elif not isinstance(expected_hash, str) or not DIGEST_PATTERN.fullmatch(expected_hash):
                counters['invalid_stored_sha256'] += 1
            elif not hmac.compare_digest(digest.hexdigest(), expected_hash.lower()):
                counters['stored_sha256_mismatch'] += 1
            else:
                counters['sha256_matches'] += 1
    expected = (
        'documents_total', 'published_active', 'revoked', 'av_attestation_unknown',
        'unsafe_stored_name', 'missing_or_symlink_file', 'out_of_bounds_size',
        'invalid_pdf_container', 'bounded_container_checked',
        'missing_stored_sha256', 'invalid_stored_sha256',
        'stored_sha256_mismatch', 'sha256_matches',
    )
    summary = {key: counters[key] for key in expected}
    # Do not treat a good hash as an anti-malware clearance.
    summary.update({
        'mode': 'OFFLINE READ-ONLY INVENTORY',
        'malware_scanned': False,
        'data_mutated': False,
        'release_gate': 'HOLD / NO-GO',
        'requires_independent_av_review': bool(counters['documents_total']),
    })
    return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db-file', type=Path, required=True, help='OFFLINE SQLite snapshot, never production DB')
    p.add_argument('--storage-dir', type=Path, required=True, help='OFFLINE copy of upload files')
    p.add_argument('--confirm-offline-copy', action='store_true', required=True,
                   help='Explicitly acknowledge that both paths are closed, offline test copies')
    args = p.parse_args(argv)
    try:
        result = summarize(args.db_file, args.storage_dir)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print('FAIL/HOLD: Offline inventory unavailable (' + type(exc).__name__ + ').', file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
