"""Explicit portable Windows ClamAV companion for the synthetic portal.

No registry, service, firewall, ACL, global PATH, portal DB or account changes.
The package URL/hash are pinned to the official vendor release. Native execution
must still be checked on the user's Windows computer; Linux tests use fixtures.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile

from clamd_preflight import exchange, probe

SOURCE = Path(__file__).resolve().parents[1]
VERSION = '1.5.4'
PREFIX = 'clamav-1.5.4.win.x64'
ASSET_URL = 'https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip'
ASSET_SHA = '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'
ASSET_SIZE = 225774978
KIND = 'PatientPortalSyntheticPortableScanner'
GATE = 'HOLD / NO-GO'
COMPONENT_FILES = {'START_CLAMAV_WINDOWS.cmd', 'CHECK_CLAMAV_WINDOWS.cmd', 'CLAMAV_WINDOWS_BG.md',
                   'tools/windows_clamav.py', 'tools/clamd_preflight.py'}


class ScannerError(RuntimeError):
    pass


class ScannerBusy(ScannerError):
    pass


def sha256(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def write_json(path, value):
    temporary = path.with_name(path.name + '.next-' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
    temporary.replace(path)


def regular(path):
    return not path.is_symlink() and path.is_file() and path.stat().st_nlink == 1


def source_check():
    try:
        records = {}
        for line in (SOURCE / 'SCANNER_COMPONENT_SHA256.txt').read_text().splitlines():
            digest, relative = line.split('  ', 1)
            if relative not in COMPONENT_FILES or relative in records or not re.fullmatch('[0-9a-f]{64}', digest):
                raise ValueError()
            records[relative] = digest
        if set(records) != COMPONENT_FILES:
            raise ValueError()
        for relative, digest in records.items():
            path = SOURCE / relative
            if not regular(path) or sha256(path) != digest:
                raise ValueError()
    except (OSError, ValueError) as exc:
        raise ScannerError('Липсващ/променен файл. Извлечете целия scanner ZIP в нова папка.') from exc


def guard_windows():
    if os.environ.get('PORTAL_ENV', '').lower() == 'production':
        raise ScannerError('Тази добавка е само за изолирания synthetic портал.')
    if os.name != 'nt' or sys.maxsize <= 2**32 or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise ScannerError('Нужни са Windows64 x64 и Python3.13/3.12.')
    if sys.version_info[:2] not in ((3, 13), (3, 12)):
        raise ScannerError('Използвайте Python3.13 или3.12.')
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise ScannerError('Стартирайте като обикновен потребител, без Administrator.')


def default_root():
    value = os.environ.get('LOCALAPPDATA')
    if not value or value.startswith('\\\\'):
        raise ScannerError('Нужна е локална LOCALAPPDATA папка.')
    return Path(value) / 'PatientPortal/ClamAV-Portable1'


def owned_root(path, *, create=False):
    path = Path(path)
    if path.is_symlink():
        raise ScannerError('Неподдържана scanner папка.')
    root = path.resolve()
    if root.is_relative_to(SOURCE):
        raise ScannerError('Scanner runtime трябва да е извън source.')
    if not root.exists() and create:
        root.parent.mkdir(parents=True, exist_ok=True)
        root.mkdir(mode=0o700)
        marker = {'kind': KIND, 'version': 1, 'instance_id': secrets.token_hex(16),
                  'synthetic_only': True, 'release_gate': GATE, 'asset_sha256': ASSET_SHA,
                  'last_update_ok': False}
        write_json(root / 'scanner.json', marker)
        fd = os.open(root / 'scanner-lock.sqlite3', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        db = sqlite3.connect(root / 'scanner-lock.sqlite3')
        try:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('CREATE TABLE owner (instance_id TEXT NOT NULL)')
            db.execute('INSERT INTO owner VALUES (?)', (marker['instance_id'],))
            db.commit()
        finally:
            db.close()
        for name in ('snapshots', 'tmp', 'logs'):
            (root / name).mkdir(mode=0o700)
    try:
        if not regular(root / 'scanner.json') or not regular(root / 'scanner-lock.sqlite3'):
            raise ValueError()
        marker = json.loads((root / 'scanner.json').read_text(encoding='utf-8'))
        if (marker.get('kind') != KIND or marker.get('version') != 1 or marker.get('synthetic_only') is not True
                or marker.get('release_gate') != GATE or marker.get('asset_sha256') != ASSET_SHA
                or not re.fullmatch('[0-9a-f]{32}', marker.get('instance_id', ''))):
            raise ValueError()
    except (OSError, ValueError, TypeError) as exc:
        raise ScannerError('Непозната scanner папка. Няма overwrite/adoption на чужда инсталация.') from exc
    return root, marker


@contextmanager
def lease(root, marker):
    db = sqlite3.connect((root / 'scanner-lock.sqlite3').as_uri() + '?mode=rw', uri=True, timeout=0)
    try:
        try:
            db.execute('BEGIN EXCLUSIVE')
            if db.execute('SELECT instance_id FROM owner').fetchall() != [(marker['instance_id'],)]:
                raise ScannerError('Повредено scanner lock състояние.')
        except sqlite3.Error as exc:
            if getattr(exc, 'sqlite_errorcode', None) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise ScannerBusy('Scanner-ът/обновяването вече работи в друг прозорец.') from exc
            raise ScannerError('Невалидна scanner lock база.') from exc
        yield
    finally:
        db.close()


class VendorRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.hostname not in {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}:
            raise ScannerError('Неочакван redirect от official download.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_package(target, *, opener=None, expected_size=ASSET_SIZE, expected_sha=ASSET_SHA):
    if target.exists():
        if not regular(target) or target.stat().st_size != expected_size or sha256(target) != expected_sha:
            raise ScannerError('Checksum mismatch на portable пакета; нищо не е изпълнено.')
        return
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), VendorRedirect())
    part = target.with_name(target.name + '.part-' + secrets.token_hex(8))
    print('Изтегляне на official Windows ClamAV пакет (около226 MB)...', flush=True)
    total = 0
    digest = hashlib.sha256()
    try:
        fd = os.open(part, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as output, opener.open(ASSET_URL, timeout=30) as reply:
            if reply.status != 200:
                raise ScannerError('Official download отказа заявката.')
            while block := reply.read(1024 * 1024):
                total += len(block)
                if total > expected_size:
                    raise ScannerError('Невалиден размер на official пакета.')
                digest.update(block)
                output.write(block)
        if total != expected_size or digest.hexdigest() != expected_sha:
            raise ScannerError('Official package size/checksum mismatch; няма изпълнение.')
        part.replace(target)
    finally:
        part.unlink(missing_ok=True)


def safe_name(name):
    path = PurePosixPath(name)
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {p + str(n) for p in ('COM', 'LPT') for n in range(1, 10)}
    if (not name or any(c in name for c in '\\:"<>|?*') or path.is_absolute()
            or any(p in ('.', '..') or p.rstrip(' .') != p or p.split('.')[0].upper() in reserved
                   for p in name.rstrip('/').split('/'))):
        raise ScannerError('Опасен path в portable ZIP.')
    return path


def runtime_member(info):
    path = safe_name(info.filename)
    return (not info.is_dir() and path.parts[0] == PREFIX and
            (path.suffix.lower() in {'.exe', '.dll', '.crt'}
             or path.name.lower().startswith(('license', 'copying', 'copyright', 'readme'))))


def extract_runtime(archive, target):
    if target.exists():
        raise ScannerError('Няма overwrite на съществуващ runtime.')
    with zipfile.ZipFile(archive) as zipped:
        seen = set()
        infos = zipped.infolist()
        if len(infos) > 3000 or sum(i.file_size for i in infos) > 1200 * 1024**2:
            raise ScannerError('Невалидни ZIP граници.')
        for info in infos:
            safe_name(info.filename)
            if (info.filename in seen or info.orig_filename != info.filename
                    or stat.S_ISLNK(info.external_attr >> 16)):
                raise ScannerError('Невалиден/дублиран ZIP entry.')
            seen.add(info.filename)
        selected = [i for i in infos if runtime_member(i)]
        needed = {PREFIX + '/' + n for n in ('clamd.exe', 'freshclam.exe', 'sigtool.exe', 'certs/clamav.crt')}
        if not needed <= {i.filename for i in selected}:
            raise ScannerError('Непълен official runtime.')
        target.mkdir(mode=0o700)
        records = {}
        for info in selected:
            destination = target / info.filename
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with zipped.open(info) as source, destination.open('xb') as output:
                shutil.copyfileobj(source, output)
            records[info.filename] = sha256(destination)
    for name in ('clamd.exe', 'freshclam.exe', 'sigtool.exe'):
        with (target / PREFIX / name).open('rb') as file:
            header = file.read(64)
            if len(header) < 64 or header[:2] != b'MZ':
                raise ScannerError('Невалиден native executable header.')
            file.seek(int.from_bytes(header[60:64], 'little'))
            pe = file.read(6)
            if pe != b'PE\0\0\x64\x86':
                raise ScannerError('Portable пакетът не е x64 PE.')
    return records


def binary_runtime(root, marker):
    download_package(root / 'official-package.zip')
    directory = root / 'runtime'
    if directory.is_symlink() or not directory.resolve().is_relative_to(root):
        raise ScannerError('Невалиден runtime path.')
    if not directory.exists():
        stage = root / ('runtime-stage-' + secrets.token_hex(8))
        records = extract_runtime(root / 'official-package.zip', stage)
        stage.rename(directory)
        marker['binary_hashes'] = records
        write_json(root / 'scanner.json', marker)
    records = marker.get('binary_hashes', {})
    if not records:
        raise ScannerError('Непълен runtime. Порталът и данните не са променени.')
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    if actual != set(records) or any(p.is_symlink() for p in directory.rglob('*')):
        raise ScannerError('Неочаквани runtime файлове.')
    for name, expected in records.items():
        safe_name(name)
        if not regular(directory / name) or sha256(directory / name) != expected:
            raise ScannerError('Portable binary checksum mismatch.')
    return directory / PREFIX


def native_environment(binary):
    env = os.environ.copy()
    env.update(TZ='UTC0', LC_ALL='C', CVD_CERTS_DIR=str(binary / 'certs'))
    return env


def native(binary, name, args, *, timeout=900):
    result = subprocess.run([str(binary / name), *args], cwd=binary, env=native_environment(binary),
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
    if result.returncode:
        raise ScannerError('Native ' + name + ' приключи с код ' + str(result.returncode) + '. Няма scanner готовност.')
    return result.stdout


def config_path(path):
    text = path.as_posix()
    if any(c in text for c in ('"', '\n', '\r')):
        raise ScannerError('Невалиден конфигурационен path.')
    return '"' + text + '"'


def freshclam_config(binary, database):
    return (f'DatabaseDirectory {config_path(database)}\nCVDCertsDirectory {config_path(binary / "certs")}\n'
            'DatabaseMirror database.clamav.net\nScriptedUpdates no\nTestDatabases yes\nBytecode yes\n'
            'MaxAttempts 1\nConnectTimeout 15\nReceiveTimeout 60\nLogVerbose no\n')


def clamd_config(root, binary, database):
    return (f'DatabaseDirectory {config_path(database)}\nCVDCertsDirectory {config_path(binary / "certs")}\n'
            f'TemporaryDirectory {config_path(root / "tmp")}\n'
            f'LogFile {config_path(root / "logs/clamd.log")}\n'
            'Foreground yes\nTCPSocket 3310\nTCPAddr 127.0.0.1\nEnableShutdownCommand no\n'
            'LogFileMaxSize 1M\nLogRotate yes\nLogTime yes\nLogClean no\nLogVerbose no\n'
            'ExtendedDetectionInfo no\nStreamMaxLength 20M\nMaxFileSize 20M\nMaxScanSize 80M\n'
            'MaxScanTime 30000\nMaxRecursion 12\nMaxFiles 1000\nAlertExceedsMax yes\n'
            'MaxThreads 2\nMaxQueue 4\nReadTimeout 10\nCommandReadTimeout 10\nSendBufTimeout 200\n'
            'SelfCheck 0\nConcurrentDatabaseReload no\n')


def database_directory(root, marker):
    value = marker.get('signature_dir', '')
    if not re.fullmatch(r'snapshots/[0-9a-f]{32}/db', value):
        raise ScannerError('Няма подготвен signature snapshot.')
    path = root / value
    if path.is_symlink() or not path.is_dir() or not path.resolve().is_relative_to(root):
        raise ScannerError('Невалиден signature snapshot.')
    return path


def database_records(binary, database, *, run=native):
    for path in database.iterdir():
        allowed = (path.name in {'main.cvd', 'daily.cvd', 'bytecode.cvd', 'freshclam.dat'}
                   or re.fullmatch(r'(main|daily|bytecode)-[0-9]+\.cvd\.sign', path.name))
        if not allowed or not regular(path):
            raise ScannerError('Неочакван/неподписан database файл.')
    records = []
    for name in ('main', 'daily', 'bytecode'):
        path = database / (name + '.cvd')
        if not regular(path):
            raise ScannerError('Непълен signature snapshot.')
        output = run(binary, 'sigtool.exe', ['--cvdcertsdir=' + str(binary / 'certs'), '--info', str(path)], timeout=60)
        if not re.search(r'^Verification OK\.$', output, re.M):
            raise ScannerError('CVD digital signature verification failed.')
        fields = dict(re.findall(r'^(Build time|Version|Signatures): ([^\r\n]+)$', output, re.M))
        if len(fields) != 3:
            raise ScannerError('Невалидни CVD metadata.')
        records.append({'database': name, **fields, 'sha256': sha256(path), 'verified': True})
    return records


def fresh_records(records, *, now=None):
    try:
        daily = next(r for r in records if r['database'] == 'daily')
        stamp = datetime.strptime(daily['Build time'], '%d %b %Y %H:%M %z')
        return timedelta(0) <= (now or datetime.now(timezone.utc)) - stamp <= timedelta(hours=48)
    except (ValueError, KeyError, StopIteration, TypeError):
        return False


def update_snapshot(root, marker, binary, *, run=native, now=None):
    now = now or datetime.now(timezone.utc)
    previous = marker.get('last_update_attempt_utc')
    if previous and now - datetime.fromisoformat(previous) < timedelta(hours=1):
        raise ScannerError('Изчакайте поне1 час между official update опитите.')
    marker.update(last_update_attempt_utc=now.isoformat(), last_update_ok=False)
    write_json(root / 'scanner.json', marker)
    work = root / 'snapshots' / secrets.token_hex(16)
    work.mkdir(mode=0o700)
    database = work / 'db'
    database.mkdir(mode=0o700)
    if marker.get('signature_dir'):
        old = database_directory(root, marker)
        for item in marker.get('databases', []):
            original = old / (item['database'] + '.cvd')
            if not regular(original) or sha256(original) != item['sha256']:
                raise ScannerError('Променена предишна CVD база.')
        for path in old.iterdir():
            if regular(path) and (path.suffix == '.cvd' or path.name.endswith('.cvd.sign')):
                shutil.copyfile(path, database / path.name)
    config = work / 'freshclam.conf'
    config.write_text(freshclam_config(binary, database), encoding='utf-8')
    print('Обновяване на official ClamAV сигнатурите...', flush=True)
    run(binary, 'freshclam.exe', ['--config-file=' + str(config), '--no-dns'])
    records = database_records(binary, database, run=run)
    if not fresh_records(records, now=now):
        raise ScannerError('Сигнатурите са стари/бъдещи. 48h проверката не е преминала.')
    marker.update(signature_dir=database.relative_to(root).as_posix(), databases=records, last_update_ok=True)
    write_json(root / 'scanner.json', marker)
    return database


def free_port(port=3310):
    with socket.socket() as connection:
        if os.name == 'nt':
            # Windows SO_REUSEADDR can bind over an existing listener. Require
            # exclusive ownership for this precheck; do not reuse a foreign port.
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            connection.bind(('127.0.0.1', port))
        except OSError as exc:
            raise ScannerError('Порт3310 е зает. Чужд процес/инсталация няма да бъде спиран.') from exc


def version_ready():
    try:
        reply = exchange(3310, b'VERSION').decode('ascii')
        match = re.fullmatch(r'ClamAV ' + re.escape(VERSION) + r'/[0-9]+/(.+)', reply)
        if not match:
            return False
        stamp = datetime.strptime(match[1], '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc)
        return timedelta(0) <= datetime.now(timezone.utc) - stamp <= timedelta(hours=48)
    except (OSError, ValueError, UnicodeError):
        return False


def stop_owned(child):
    if child.poll() is not None:
        return
    child.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGTERM)
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def serve(root, marker, binary, database):
    config = root / 'clamd.conf'
    config.write_text(clamd_config(root, binary, database), encoding='utf-8')
    log = root / 'logs/native-process.log'
    if log.exists() and not regular(log):
        raise ScannerError('Невалиден private scanner log.')
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    options = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    with os.fdopen(fd, 'w') as output:
        child = subprocess.Popen([str(binary / 'clamd.exe'), '--config-file=' + str(config)], cwd=binary,
                                 env=native_environment(binary), stdout=output, stderr=output, **options)
    try:
        deadline = time.monotonic() + 180
        while True:
            if child.poll() is not None or time.monotonic() > deadline:
                raise ScannerError('ClamAV не стартира. Вижте CLAMAV_WINDOWS_BG.md.')
            try:
                if exchange(3310, b'PING') == b'PONG':
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.3)
        readiness = probe(port=3310, signature_timezone='UTC')
        if not readiness['protocol_passed'] or child.poll() is not None:
            raise ScannerError('PING/clean/EICAR/48h preflight не е преминал; няма готов scanner.')
        write_json(root / 'last-preflight.json', readiness)
        write_json(root / 'runtime.json', {'instance_id': marker['instance_id'], 'state': 'serving'})
        print('\nClamAV е готов на 127.0.0.1:3310. Само synthetic портал. HOLD / NO-GO.', flush=True)
        print('Оставете този прозорец отворен и се върнете в работещия портал. Спиране: Ctrl+C.', flush=True)
        while child.poll() is None:
            if not version_ready():
                raise ScannerError('Scanner readiness е загубена. Собственият процес се спира.')
            time.sleep(60)
        raise ScannerError('Собственият scanner процес приключи.')
    finally:
        stop_owned(child)
        write_json(root / 'runtime.json', {'instance_id': marker['instance_id'], 'state': 'stopped'})


def check(root, marker):
    try:
        with lease(root, marker):
            return {'ready': False, 'reason': 'OWNED_SCANNER_NOT_RUNNING', 'release_gate': GATE}
    except ScannerBusy:
        pass
    runtime = json.loads((root / 'runtime.json').read_text())
    if runtime != {'instance_id': marker['instance_id'], 'state': 'serving'}:
        return {'ready': False, 'reason': 'OWNED_SCANNER_PREPARING', 'release_gate': GATE}
    result = probe(port=3310, signature_timezone='UTC')
    return {'ready': result['protocol_passed'], 'preflight': result, 'release_gate': GATE, 'production_approved': False}


def main():
    parser = argparse.ArgumentParser(description='Portable local Windows ClamAV; synthetic only, HOLD / NO-GO')
    parser.add_argument('command', choices=('start', 'check'))
    parser.add_argument('--confirm-synthetic-local-scanner', action='store_true', required=True)
    args = parser.parse_args()
    try:
        guard_windows()
        source_check()
        root, marker = owned_root(default_root(), create=args.command == 'start')
        if args.command == 'check':
            result = check(root, marker)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['ready'] else 1
        with lease(root, marker):
            write_json(root / 'runtime.json', {'instance_id': marker['instance_id'], 'state': 'preparing'})
            free_port()
            binary = binary_runtime(root, marker)
            now = datetime.now(timezone.utc)
            previous = marker.get('last_update_attempt_utc')
            elapsed = now - datetime.fromisoformat(previous) if previous else timedelta(days=999)
            if not marker.get('last_update_ok') or elapsed >= timedelta(hours=24) or not fresh_records(marker.get('databases', [])):
                database = update_snapshot(root, marker, binary)
            else:
                database = database_directory(root, marker)
                records = database_records(binary, database)
                if not fresh_records(records):
                    raise ScannerError('48h freshness не е преминала.')
            serve(root, marker, binary, database)
        return 0
    except KeyboardInterrupt:
        print('\nСобственият ClamAV е спрян. Порталът и неговите данни са запазени.')
        return 0
    except ScannerError as exc:
        print('HOLD: ' + str(exc), file=sys.stderr)
    except Exception as exc:
        print('HOLD: scanner подготовката е спряна (' + type(exc).__name__ + '). Вижте CLAMAV_WINDOWS_BG.md.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
