"""Explicit encrypted backup and separate restore drill for the synthetic desktop.

Uses the existing candidate AES-GCM format and lifecycle locks. No production
paths, replacement of the active data directory, service changes or secret argv.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
import warnings

import desktop_start as desktop
from candidate_runtime import GATE, read_config, private_write

PROJECT = Path(__file__).resolve().parents[1]
KIND = 'PatientPortalSyntheticDesktopBackups'
PORT = 8001
URL = f'http://127.0.0.1:{PORT}/login'
ARCHIVE_NAME = r'synthetic-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\.ppbk'
RESTORE_NAME = r'restored-[0-9a-f]{32}'


class BackupError(RuntimeError):
    pass


def regular(path):
    return not path.is_symlink() and path.is_file() and path.stat().st_nlink == 1


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def state_write(path, value):
    temporary = path.with_name(path.name + '.next-' + secrets.token_hex(8))
    try:
        private_write(temporary, json.dumps(value, ensure_ascii=False, indent=2))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def state_read(path):
    if not regular(path):
        raise BackupError('Липсва валидно локално състояние за тази операция.')
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise BackupError('Невалидно локално състояние.')
    return value


def existing_desktop(path):
    path = Path(path)
    if not path.is_dir() or path.is_symlink():
        raise BackupError('Не е намерен подготвеният тестов портал. Няма автоматична инициализация.')
    return desktop.create_or_read_root(path)


def backup_folder(root, marker, *, create=False):
    path = root / 'backups-v17'
    expected = {'kind': KIND, 'version': 1, 'desktop_instance': marker['instance_id'],
                'synthetic_only': True, 'release_gate': GATE}
    if not path.exists() and create:
        path.mkdir(mode=0o700)
        private_write(path / 'owner.json', json.dumps(expected))
    if (path.is_symlink() or not path.is_dir() or path.resolve().parent != root
            or state_read(path / 'owner.json') != expected):
        raise BackupError('Непозната папка за архиви. Няма overwrite/adoption.')
    return path


def passphrase(*, repeat=False):
    if not sys.stdin.isatty():
        raise BackupError('Паролата за архива се въвежда само в интерактивния локален прозорец.')
    with warnings.catch_warnings():
        # getpass otherwise falls back to visible input when echo suppression
        # fails. Refuse that fallback before it can read a passphrase.
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            value = getpass.getpass('Парола за архива (поне 16 знака; въвеждането е скрито): ')
            if len(value) < 16:
                raise BackupError('Нужна е парола за архива с поне 16 знака.')
            if repeat and value != getpass.getpass('Повтори паролата за архива: '):
                raise BackupError('Двете въведени пароли за архива не съвпадат.')
        except getpass.GetPassWarning as exc:
            raise BackupError('Скритото въвеждане не е достъпно. Използвай обикновения локален CMD прозорец.') from exc
    return value


@contextmanager
def stopped_desktop(root, marker):
    # This also prevents START_WINDOWS from starting during maintenance. The
    # underlying backup API separately excludes every candidate worker/CLI.
    with desktop.desktop_lease(root, marker):
        yield


def create_backup(root, marker, *, ask=passphrase):
    import candidate_backup as backup
    with stopped_desktop(root, marker):
        data, config = read_config(root / 'data')
        # Reject worker-style/manual serve leases before asking for a secret.
        from candidate_runtime import acquire_lifecycle
        guard = acquire_lifecycle(data, config['instance_id'], exclusive=True)
        guard.close()
        folder = backup_folder(root, marker, create=True)
        key = ask(repeat=True)
        name = 'synthetic-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(8) + '.ppbk'
        archive = folder / name
        count = backup.create(data, archive, key)
        state_write(folder / 'last-backup.json', {'file': name, 'sha256': digest(archive),
                    'bytes': archive.stat().st_size, 'candidate_instance': config['instance_id']})
        return archive, count


def latest_backup(folder):
    state = state_read(folder / 'last-backup.json')
    if (not re.fullmatch(ARCHIVE_NAME, state.get('file', ''))
            or not re.fullmatch('[0-9a-f]{64}', state.get('sha256', ''))
            or not re.fullmatch('[0-9a-f]{32}', state.get('candidate_instance', ''))):
        raise BackupError('Невалиден запис за последния собствен архив.')
    archive = folder / state['file']
    if (not regular(archive) or archive.stat().st_size != state.get('bytes')
            or digest(archive) != state['sha256']):
        raise BackupError('Последният архив е липсващ или променен. Няма възстановяване.')
    return archive, state


def restore_test(root, marker, *, ask=passphrase):
    import candidate_backup as backup
    with stopped_desktop(root, marker):
        folder = backup_folder(root, marker)
        archive, state = latest_backup(folder)
        # Restore works even when the original application data is damaged;
        # only the desktop owner and our archive index are needed here.
        key = ask(repeat=False)
        target = folder / ('restored-' + secrets.token_hex(16))
        count = backup.restore(archive, target, key)
        _, config = read_config(target)
        if config['instance_id'] != state['candidate_instance']:
            raise BackupError('Възстановеният архив е за различен тестов кандидат.')
        state_write(folder / 'last-restore.json', {'directory': target.name,
                    'candidate_instance': config['instance_id'], 'archive_sha256': state['sha256']})
        return target, count


def restored_data(folder):
    state = state_read(folder / 'last-restore.json')
    if (not re.fullmatch(RESTORE_NAME, state.get('directory', ''))
            or not re.fullmatch('[0-9a-f]{32}', state.get('candidate_instance', ''))
            or not re.fullmatch('[0-9a-f]{64}', state.get('archive_sha256', ''))):
        raise BackupError('Няма валиден собствен резултат от пробното възстановяване.')
    path = folder / state['directory']
    if path.is_symlink() or path.resolve().parent != folder:
        raise BackupError('Неподдържан път към възстановения тестов портал.')
    root, config = read_config(path)
    if config['instance_id'] != state['candidate_instance']:
        raise BackupError('Различна идентичност на възстановения тестов портал.')
    return root


def serve_restored(root, marker, *, browser=webbrowser.open):
    with stopped_desktop(root, marker):
        folder = backup_folder(root, marker)
        data = restored_data(folder)
        with socket.socket() as sock:
            option = socket.SO_EXCLUSIVEADDRUSE if os.name == 'nt' else socket.SO_REUSEADDR
            sock.setsockopt(socket.SOL_SOCKET, option, 1)
            try:
                sock.bind(('127.0.0.1', PORT))
            except OSError as exc:
                raise BackupError('Порт 8001 е зает. Чужд процес няма да бъде спиран.') from exc
        command = [sys.executable, '-B', str(PROJECT / 'tools/run_candidate.py'), 'serve',
                   '--data-dir', str(data), '--port', str(PORT), '--workers', '2', '--require-fresh-scanner']
        options = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
        child = subprocess.Popen(command, cwd=PROJECT, **options)
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + 40
            while True:
                if child.poll() is not None:
                    raise BackupError('Възстановеният портал не стартира.')
                try:
                    with opener.open(URL, timeout=1) as response:
                        if response.status == 200:
                            break
                except (urllib.error.URLError, OSError):
                    pass
                if time.monotonic() > deadline:
                    raise BackupError('Изтече времето за стартиране на възстановения портал.')
                time.sleep(0.2)
            print('ПРОБНО ВЪЗСТАНОВЯВАНЕ: ' + URL, flush=True)
            print('Проверете тестовите настройки и публикувания PDF. Спиране: Ctrl+C. HOLD / NO-GO.', flush=True)
            try:
                browser(URL)
            except OSError:
                print('Отворете адреса ръчно в браузъра.', flush=True)
            child.wait()
            if child.returncode:
                raise BackupError('Възстановеният тестов портал приключи с грешка.')
        finally:
            desktop.stop_owned(child)


def main():
    parser = argparse.ArgumentParser(description='Encrypted synthetic desktop backup / separate restore; HOLD / NO-GO')
    parser.add_argument('command', choices=('create', 'restore-test', 'serve-restored'))
    parser.add_argument('--confirm-synthetic-desktop-backup', action='store_true', required=True)
    args = parser.parse_args()
    try:
        desktop.guard_runtime()
        desktop.verify_source()
        root, marker = existing_desktop(desktop.default_root())
        if args.command == 'serve-restored':
            serve_restored(root, marker)
        else:
            path, count = (create_backup if args.command == 'create' else restore_test)(root, marker)
            print('Успешно: ' + str(count) + ' файла. ' + str(path), flush=True)
            print('Оригиналният портал е запазен. Само синтетични данни. HOLD / NO-GO.', flush=True)
        return 0
    except KeyboardInterrupt:
        print('\nОперацията е прекъсната. Оригиналният тестов портал е запазен.')
        return 1
    except (BackupError, desktop.SetupError) as exc:
        print('HOLD: ' + str(exc), file=sys.stderr)
        print('За архивиране спри собствения тестов портал с Ctrl+C и изчакай приключването му.', file=sys.stderr)
    except Exception as exc:
        print('HOLD: операцията е отказана (' + type(exc).__name__ + '). Виж WINDOWS_BACKUP_BG.md.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
