"""Encrypted, authenticated backups for the single-node SQLite portal.

Backups use streaming AES-256-GCM + scrypt and tar.gz. The database is snapshotted
with sqlite3.backup(), so copying an active WAL file is never needed.
Offline restoration is always into a NEW empty directory; never overwrite a live portal.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import getpass
import hashlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from dotenv import load_dotenv

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')
HEADER = b'PPBK16\0'  # 7-byte versioned magic
MAX_BACKUP_MEMBERS = 200000


def sources():
    url = os.getenv('DATABASE_URL', f"sqlite:///{BASE / 'private_data' / 'portal.sqlite3'}")
    if not url.startswith('sqlite:///'):
        raise ValueError('This backup utility supports SQLite only. Use a reviewed PostgreSQL backup procedure.')
    db_path = Path(url[len('sqlite:///'):])
    if not db_path.is_absolute():
        db_path = (BASE / db_path).resolve()
    upload = Path(os.getenv('PRIVATE_STORAGE', str(BASE / 'private_data' / 'uploads')))
    if not upload.is_absolute():
        upload = (BASE / upload).resolve()
    if not db_path.is_file():
        raise ValueError('SQLite database does not exist; check DATABASE_URL')
    if not upload.is_dir():
        raise ValueError('Private upload directory does not exist')
    return db_path, upload


def key_for(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 16:
        raise ValueError('Backup passphrase must have at least 16 characters')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode('utf-8'))


class EncryptWriter:
    def __init__(self, out, encryptor):
        self.out, self.encryptor = out, encryptor

    def write(self, data):
        if data:
            self.out.write(self.encryptor.update(data))
        return len(data)

    def flush(self):
        self.out.flush()


class DecryptReader:
    def __init__(self, handle, decryptor, remaining):
        self.handle = handle
        self.decryptor = decryptor
        self.remaining = remaining
        self.finished = False

    def read(self, size=-1):
        if self.remaining <= 0:
            if not self.finished:
                self.decryptor.finalize()  # raises InvalidTag on tampering/wrong passphrase
                self.finished = True
            return b''
        n = min(self.remaining, 1024 * 1024 if size is None or size < 0 else size)
        if n == 0:
            return b''
        chunk = self.handle.read(n)
        if len(chunk) != n:
            raise ValueError('Truncated encrypted backup')
        self.remaining -= n
        return self.decryptor.update(chunk)

    def finish(self):
        while self.read(1024 * 1024):
            pass


def add_file(tar, path, arcname, manifest):
    info = tar.gettarinfo(str(path), arcname=arcname)
    if not info.isfile():
        raise ValueError('Symlink or non-regular file in private storage; refusing backup')
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            digest.update(chunk)
    manifest[arcname] = dict(sha256=digest.hexdigest(), size=info.size)
    with path.open('rb') as f:
        tar.addfile(info, f)


def create_backup(output: Path, passphrase: str, *, extra_files=None):
    db_path, upload_path = sources()
    output = output.resolve()
    if output.exists():
        raise FileExistsError('Output already exists; refusing to overwrite an existing backup')
    if output.is_relative_to(upload_path) or output.is_relative_to(db_path.parent):
        raise ValueError('Store encrypted backups outside the private_data directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    # sqlite3.backup produces a transactionally consistent snapshot, even with WAL.
    # The staging snapshot is temporary plaintext; the host disk MUST be encrypted.
    with tempfile.TemporaryDirectory(prefix='.snapshot-', dir=str(db_path.parent)) as temp:
        snapshot = Path(temp) / 'portal.sqlite3'
        # sqlite3.Connection.__exit__ commits/rolls back but DOES NOT close the
        # connection. On Windows an open connection keeps snapshot.sqlite3
        # locked and TemporaryDirectory cleanup fails with WinError 32.
        # Explicitly close both handles before reading/removing the snapshot.
        with closing(sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)) as src:
            with closing(sqlite3.connect(snapshot)) as dest:
                src.backup(dest)
        salt, nonce = os.urandom(16), os.urandom(12)
        key = key_for(passphrase, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        manifest = {}
        try:
            with output.open('xb') as out:
                os.chmod(output, 0o600)
                out.write(HEADER + salt + nonce)
                with tarfile.open(fileobj=EncryptWriter(out, cipher), mode='w|gz') as tar:
                    add_file(tar, snapshot, 'portal.sqlite3', manifest)
                    for file in sorted(upload_path.rglob('*')):
                        if file.is_symlink():
                            raise ValueError('Symlink in upload directory; refusing backup')
                        if file.is_file():
                            add_file(tar, file, 'uploads/' + file.relative_to(upload_path).as_posix(), manifest)
                    for name,source in (extra_files or {}).items():
                        if name not in {'candidate.json','candidate-secret','synthetic-accounts.json'}:
                            raise ValueError('Unexpected candidate backup metadata')
                        add_file(tar,Path(source),name,manifest)
                    payload = json.dumps({'version': 1, 'files': manifest}, sort_keys=True).encode()
                    entry = tarfile.TarInfo('manifest.json')
                    entry.size, entry.mode = len(payload), 0o600
                    tar.addfile(entry, io.BytesIO(payload))
                out.write(cipher.finalize())
                out.write(cipher.tag)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
    return len(manifest)


def verify_or_restore(path: Path, passphrase: str, destination: Path | None = None, *, candidate_metadata=False):
    path = path.resolve()
    if not path.is_file():
        raise ValueError('Backup file not found')
    header_len = len(HEADER) + 16 + 12
    with path.open('rb') as encrypted:
        size = path.stat().st_size
        if size <= header_len + 16:
            raise ValueError('Backup file too short')
        header = encrypted.read(header_len)
        if not header.startswith(HEADER):
            raise ValueError('Unknown backup format')
        salt = header[len(HEADER):len(HEADER)+16]
        nonce = header[-12:]
        encrypted.seek(-16, 2)
        tag = encrypted.read(16)
        encrypted.seek(header_len)
        decryptor = Cipher(algorithms.AES(key_for(passphrase, salt)), modes.GCM(nonce, tag)).decryptor()
        reader = DecryptReader(encrypted, decryptor, size-header_len-16)
        expected, observed, count = None, {}, 0
        stage = None
        if destination is not None:
            destination = destination.resolve()
            if destination.exists():
                raise ValueError('Restore destination MUST NOT exist; original files are never overwritten')
            destination.parent.mkdir(parents=True, exist_ok=True)
            stage = Path(tempfile.mkdtemp(prefix='.restore-', dir=str(destination.parent)))
        try:
            with tarfile.open(fileobj=reader, mode='r|gz') as archive:
                for item in archive:
                    count += 1
                    if count > MAX_BACKUP_MEMBERS or not item.isfile() or item.size < 0:
                        raise ValueError('Unexpected backup member type/count')
                    name = item.name
                    parts = Path(name).parts
                    allowed_metadata={'candidate.json','candidate-secret','synthetic-accounts.json'} if candidate_metadata else set()
                    if (name not in ('manifest.json', 'portal.sqlite3') and name not in allowed_metadata and
                        not (len(parts) >= 2 and parts[0] == 'uploads')):
                        raise ValueError('Unexpected path in backup')
                    if '..' in parts or Path(name).is_absolute() or '\\' in name:
                        raise ValueError('Unsafe backup path')
                    if name in observed:
                        raise ValueError('Duplicate backup member')
                    stream = archive.extractfile(item)
                    if stream is None:
                        raise ValueError('Unreadable member')
                    if name == 'manifest.json':
                        if item.size > 16 * 1024 * 1024:
                            raise ValueError('Manifest too large')
                        expected = json.loads(stream.read())
                        continue
                    digest, length = hashlib.sha256(), 0
                    dest = stage / name if stage else None
                    if dest:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                    with dest.open('xb') if dest else open(os.devnull, 'wb') as out:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            length += len(chunk)
                            if length > item.size:
                                raise ValueError('Member size mismatch')
                            digest.update(chunk)
                            out.write(chunk)
                    if length != item.size:
                        raise ValueError('Member truncated')
                    observed[name] = {'sha256': digest.hexdigest(), 'size': length}
            reader.finish()  # REQUIRED: authenticate the complete AES-GCM ciphertext
            if (expected is None or expected.get('version') != 1
                or expected.get('files') != observed or 'portal.sqlite3' not in observed):
                raise ValueError('Backup manifest/hash mismatch')
            if stage is not None:
                # Only an authenticated archive is renamed into the requested directory.
                os.replace(stage, destination)
                stage = None
            return len(observed)
        finally:
            if stage is not None:
                shutil.rmtree(stage, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description='Encrypted backup or offline restore; SQLite only')
    sub = parser.add_subparsers(dest='cmd', required=True)
    sub.add_parser('create').add_argument('--output', required=True, type=Path)
    sub.add_parser('verify').add_argument('--file', required=True, type=Path)
    restore = sub.add_parser('restore')
    restore.add_argument('--file', required=True, type=Path)
    restore.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    key = getpass.getpass('BACKUP PASSPHRASE (16+ chars; no recovery if lost): ')
    if args.cmd == 'create':
        confirm = getpass.getpass('Repeat backup passphrase: ')
        if key != confirm:
            raise SystemExit('Passphrases do not match')
        count = create_backup(args.output, key)
        print(f'Encrypted backup created ({count} data files). Verify it before relying on it.')
    elif args.cmd == 'verify':
        count = verify_or_restore(args.file, key)
        print(f'Verified AES-GCM authentication + {count} file hashes.')
    else:
        count = verify_or_restore(args.file, key, args.destination)
        print(f'Restored {count} files to a NEW offline staging folder; review before deploying.')


if __name__ == '__main__':
    main()
