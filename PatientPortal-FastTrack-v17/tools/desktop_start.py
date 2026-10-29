"""Standard-library bootstrap for the local synthetic desktop portal.

Uses source-relative paths, a private versioned LOCALAPPDATA store and explicit
native exit checks. Never installs Python/ClamAV/services, changes OS policy,
adopts another store or prints generated account values.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'app'))
from candidate_runtime import CandidateError, GATE, private_write, read_config, root_path

KIND = 'PatientPortalSyntheticDesktop'
URL = 'http://127.0.0.1:8000/login'
SUPPORTED = {(3, 12), (3, 13)}
PACKAGE_PROBE = '''import importlib.metadata as m, json, sys
try:
    required = json.loads(sys.argv[1])
    ok = all(m.version(name) == version for name, version in required.items())
except m.PackageNotFoundError:
    ok = False
sys.exit(0 if ok else 1)
'''


class SetupError(RuntimeError):
    pass


def guard_runtime():
    if os.environ.get('PORTAL_ENV', '').lower() == 'production':
        raise SetupError('Тестовото стартиране е забранено в production режим.')
    if sys.version_info[:2] not in SUPPORTED:
        raise SetupError('Използвайте Python 3.13 или 3.12 чрез py launcher.')
    if os.name == 'nt':
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            raise SetupError('Стартирайте с обикновен потребител, без Administrator.')
        if str(PROJECT).startswith('\\\\'):
            raise SetupError('Разархивирайте на локален диск, извън мрежова папка.')
    if (PROJECT / 'app/.env').exists() or (PROJECT / '.env').exists():
        raise SetupError('Използвайте чистата тестова папка без .env файл.')


def verify_source():
    try:
        manifest = json.loads((PROJECT / 'RELEASE_SHA256.json').read_text(encoding='utf-8'))
        for relative, expected in manifest.items():
            path = PROJECT / relative
            if not path.resolve().is_relative_to(PROJECT) or path.is_symlink() or not path.is_file():
                raise ValueError()
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError()
        if not {'tools/run_candidate.py', 'tools/desktop_start.py', 'TEST_ENV_VERSIONS.txt', 'MANIFEST_SHA256.json'} <= manifest.keys():
            raise ValueError()
    except (OSError, ValueError, TypeError) as exc:
        raise SetupError('Липсващ/променен файл. Разархивирайте целия оригинален пакет отново в нова папка.') from exc


def default_root():
    value = os.environ.get('LOCALAPPDATA')
    if os.name != 'nt' or not value:
        raise SetupError('START_WINDOWS.cmd е за Windows с LOCALAPPDATA.')
    return Path(value) / 'PatientPortal/FastTrack15'


def create_or_read_root(path):
    guard_runtime()
    root = root_path(path)
    if not root.exists():
        root.parent.mkdir(parents=True, exist_ok=True)
        root.mkdir(mode=0o700)
        marker = {'kind': KIND, 'version': 1, 'source_release': 15,
                  'instance_id': secrets.token_hex(16), 'synthetic_only': True, 'release_gate': GATE}
        private_write(root / 'desktop.json', json.dumps(marker, indent=2))
        lock = root / 'desktop-lock.sqlite3'
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        db = sqlite3.connect(lock)
        try:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('CREATE TABLE marker (instance_id TEXT NOT NULL)')
            db.execute('INSERT INTO marker VALUES (?)', (marker['instance_id'],))
            db.commit()
        finally:
            db.close()
    try:
        for name in ('desktop.json', 'desktop-lock.sqlite3'):
            p = root / name
            if p.is_symlink() or not p.is_file() or p.stat().st_nlink != 1:
                raise ValueError()
        marker = json.loads((root / 'desktop.json').read_text(encoding='utf-8'))
        if (marker.get('kind') != KIND or marker.get('version') != 1 or marker.get('source_release') != 15
                or marker.get('synthetic_only') is not True or marker.get('release_gate') != GATE
                or not re.fullmatch(r'[0-9a-f]{32}', marker.get('instance_id', ''))):
            raise ValueError()
    except (OSError, ValueError, TypeError) as exc:
        raise SetupError('Папката с данни не е подготвена от този тестов launcher. Няма overwrite/reset.') from exc
    return root, marker


@contextmanager
def desktop_lease(root, marker):
    db = sqlite3.connect((root / 'desktop-lock.sqlite3').as_uri() + '?mode=rw', uri=True, timeout=0)
    try:
        try:
            db.execute('BEGIN EXCLUSIVE')
            if db.execute('SELECT instance_id FROM marker').fetchall() != [(marker['instance_id'],)]:
                raise SetupError('Невалиден desktop lock; не го подменяйте при работещ портал.')
        except sqlite3.Error as exc:
            raise SetupError('Порталът или подготовката вече работят. Използвайте отворения прозорец.') from exc
        yield
    finally:
        db.close()


def checked_run(command, *, stage, capture=False, timeout=None):
    result = subprocess.run(command, cwd=PROJECT, capture_output=capture, text=True, timeout=timeout)
    if result.returncode != 0:
        raise SetupError(stage + ' не завърши успешно (код ' + str(result.returncode) + '). Следващите стъпки са спрени.')
    return result


def requirements():
    result = {}
    for line in (PROJECT / 'TEST_ENV_VERSIONS.txt').read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)', line)
        if not match:
            raise SetupError('Невалиден фиксиран списък със зависимости.')
        result[match[1]] = match[2]
    return result


def environment_python(root):
    return root / ('venv/Scripts/python.exe' if os.name == 'nt' else 'venv/bin/python')


def prepare(root, *, run=checked_run):
    python = environment_python(root)
    folder = root / 'venv'
    if not folder.exists():
        run([sys.executable, '-m', 'venv', str(folder)], stage='Създаването на Python средата')
    if not python.is_file() or folder.is_symlink() or not (folder / 'pyvenv.cfg').is_file():
        raise SetupError('Непълна Python среда. Данните са запазени; вижте WINDOWS_START_BG.md.')
    run([str(python), '-B', '-c', 'import sys; sys.exit(0 if sys.version_info[:2] in ((3,12),(3,13)) else 1)'],
        stage='Проверката на Python версията', capture=True, timeout=15)
    pins = json.dumps(requirements(), separators=(',', ':'))
    try:
        run([str(python), '-B', '-c', PACKAGE_PROBE, pins], stage='Проверката на пакетите', capture=True, timeout=30)
    except SetupError:
        run([str(python), '-m', 'pip', 'install', '--only-binary=:all:', '-r', str(PROJECT / 'TEST_ENV_VERSIONS.txt')],
            stage='Инсталирането на пакетите')
        run([str(python), '-B', '-c', PACKAGE_PROBE, pins], stage='Проверката на инсталираните пакети', capture=True, timeout=30)
    candidate = root / 'data'
    if not candidate.exists():
        run([str(python), '-B', str(PROJECT / 'tools/run_candidate.py'), 'init', '--data-dir', str(candidate),
             '--confirm-synthetic-only'], stage='Подготовката на тестовите данни')
    else:
        read_config(candidate)  # read-only; no reseed/migration/adoption
    run([str(python), '-B', str(PROJECT / 'tools/run_candidate.py'), 'check', '--data-dir', str(candidate)],
        stage='Проверката на тестовите данни')
    return python, candidate


def stop_owned(child):
    if child.poll() is not None:
        return
    if os.name == 'nt':
        child.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        os.killpg(child.pid, signal.SIGTERM)
    try:
        child.wait(timeout=12)
    except subprocess.TimeoutExpired:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=5)
        else:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


def serve(python, candidate, *, browser=webbrowser.open, popen=subprocess.Popen):
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('127.0.0.1', 8000))
        except OSError as exc:
            raise SetupError('Порт 8000 е зает. Затворете предишния собствен тестов портал.') from exc
    command = [str(python), '-B', str(PROJECT / 'tools/run_candidate.py'), 'serve', '--data-dir', str(candidate),
               '--port', '8000', '--workers', '2', '--require-fresh-scanner']
    options = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    child = popen(command, cwd=PROJECT, **options)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 40
        while True:
            if child.poll() is not None:
                raise SetupError('Сървърът не стартира. Вижте съобщението над този ред.')
            try:
                with opener.open(URL, timeout=1) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, OSError):
                pass
            if time.monotonic() > deadline:
                raise SetupError('Изтече времето за стартиране на локалната страница.')
            time.sleep(0.2)
        print('\nПорталът е отворен: ' + URL, flush=True)
        print('Тестови акаунти (локален файл): ' + str(candidate / 'synthetic-accounts.json'), flush=True)
        print('Оставете този прозорец отворен. Спиране: Ctrl+C. HOLD / NO-GO.', flush=True)
        try:
            browser(URL)
        except OSError:
            print('Отворете адреса ръчно в браузъра.', flush=True)
        child.wait()
        if child.returncode:
            raise SetupError('Локалният сървър приключи с грешка.')
    finally:
        stop_owned(child)


def diagnose(path, *, scanner_check=None):
    # Read-only: no root/venv/DB creation, native installer or password reads.
    root = root_path(path)
    result = {'python': '.'.join(map(str, sys.version_info[:3])),
              'supported_python': sys.version_info[:2] in SUPPORTED,
              'source_folder': str(PROJECT), 'source_integrity': False,
              'venv_present': environment_python(root).is_file(), 'candidate_ready': False,
              'release_gate': GATE, 'production_approved': False}
    try:
        verify_source()
        result['source_integrity'] = True
    except SetupError:
        pass
    try:
        read_config(root / 'data')
        result['candidate_ready'] = True
    except (CandidateError, OSError):
        pass
    if scanner_check is None:
        from scanner_readiness import scanner_ready
        scanner_check = scanner_ready
    result['scanner_fresh'] = bool(scanner_check(3310))
    return result


def main():
    parser = argparse.ArgumentParser(description='Локален тестов Windows портал; HOLD / NO-GO')
    parser.add_argument('--diagnose', action='store_true', help='Read-only diagnostics without account values')
    args = parser.parse_args()
    try:
        guard_runtime()
        root = default_root()
        if args.diagnose:
            print(json.dumps(diagnose(root), ensure_ascii=False, indent=2))
            return 0
        verify_source()
        root, marker = create_or_read_root(root)
        with desktop_lease(root, marker):
            print('Подготовка на локален ТЕСТОВ портал. Само синтетични данни. HOLD / NO-GO.', flush=True)
            python, data = prepare(root)
            print('PDF качване/сканиране изисква локален ClamAV с актуални сигнатури.', flush=True)
            serve(python, data)
        return 0
    except KeyboardInterrupt:
        print('\nПорталът е спрян. Тестовите данни и сесиите са запазени.')
        return 0
    except SetupError as exc:
        print('HOLD: ' + str(exc), file=sys.stderr)
    except Exception as exc:
        print('HOLD: подготовката е спряна (' + type(exc).__name__ + '). Вижте WINDOWS_START_BG.md.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
