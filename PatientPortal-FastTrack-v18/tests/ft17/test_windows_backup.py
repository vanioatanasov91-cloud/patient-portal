"""Original backup checks plus desktop archive/restore drill with synthetic data.

Runs the shipping candidate server on Linux. No Windows CMD, real patient files,
native browser, real scanner or operator passphrase prompt is executed here.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import windows_backup as helper
import candidate_runtime as runtime


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix='FT17_SYNTHETIC_DESKTOP_BACKUP_') as temporary:
        root, marker = helper.desktop.create_or_read_root(Path(temporary) / 'desktop')
        runtime.initialize(root / 'data')
        yield root, marker


class DesktopBackupTests(unittest.TestCase):
    def test_passphrase_requires_tty_hidden_input_length_and_confirmation(self):
        with patch.object(helper.sys.stdin, 'isatty', return_value=False), patch.object(helper.getpass, 'getpass') as ask:
            with self.assertRaises(helper.BackupError):
                helper.passphrase()
            ask.assert_not_called()
        with patch.object(helper.sys.stdin, 'isatty', return_value=True):
            for values in (['short'], ['SYNTHETIC SECRET LONG ENOUGH', 'SYNTHETIC DIFFERENT SECRET']):
                with patch.object(helper.getpass, 'getpass', side_effect=values):
                    with self.assertRaises(helper.BackupError):
                        helper.passphrase(repeat=True)
            def no_echo_control(*args, **kwargs):
                warnings.warn('SYNTHETIC ECHO CONTROL UNAVAILABLE', helper.getpass.GetPassWarning)
                self.fail('visible fallback was allowed')
            with patch.object(helper.getpass, 'getpass', side_effect=no_echo_control):
                with self.assertRaises(helper.BackupError):
                    helper.passphrase()

    def test_missing_and_foreign_desktop_are_not_created_or_adopted(self):
        with tempfile.TemporaryDirectory(prefix='FT17_SYNTHETIC_UNKNOWN_') as temporary:
            path = Path(temporary) / 'missing'
            with self.assertRaises(helper.BackupError):
                helper.existing_desktop(path)
            self.assertFalse(path.exists())
            path.mkdir()
            keep = path / 'keep.txt'
            keep.write_text('SYNTHETIC EXISTING DIRECTORY')
            with self.assertRaises(helper.desktop.SetupError):
                helper.existing_desktop(path)
            self.assertEqual(list(path.iterdir()), [keep])

    def test_encrypted_roundtrip_keeps_original_and_creates_separate_unique_stores(self):
        with fixture() as (root, marker):
            data = root / 'data'
            originals = {name: (data / name).read_bytes() for name in ('candidate-secret', 'candidate.json', 'synthetic-accounts.json')}
            key = secrets.token_urlsafe(32)
            archive, count = helper.create_backup(root, marker, ask=lambda **_: key)
            self.assertEqual(count, 5)
            self.assertNotIn(originals['candidate-secret'], archive.read_bytes())
            one, restored_count = helper.restore_test(root, marker, ask=lambda **_: key)
            two, _ = helper.restore_test(root, marker, ask=lambda **_: key)
            self.assertEqual(restored_count, count)
            self.assertNotEqual(one, two)
            self.assertNotEqual(one, data)
            self.assertEqual(helper.restored_data(archive.parent), two)
            for name, value in originals.items():
                self.assertEqual((data / name).read_bytes(), value)
                self.assertEqual((one / name).read_bytes(), value)
            self.assertEqual((one / 'files/synthetic-legacy.pdf').read_bytes(), (data / 'files/synthetic-legacy.pdf').read_bytes())

    def test_desktop_owner_and_worker_each_refuse_backup_before_prompt(self):
        with fixture() as (root, marker):
            ask = Mock()
            with helper.desktop.desktop_lease(root, marker):
                with self.assertRaises(helper.desktop.SetupError):
                    helper.create_backup(root, marker, ask=ask)
            _, config = runtime.read_config(root / 'data')
            lease = runtime.acquire_lifecycle(root / 'data', config['instance_id'])
            try:
                with self.assertRaises(runtime.CandidateError):
                    helper.create_backup(root, marker, ask=ask)
            finally:
                lease.close()
            ask.assert_not_called()
            self.assertFalse((root / 'backups-v17').exists())

    def test_wrong_key_preserves_previous_restore_and_original(self):
        with fixture() as (root, marker):
            key = secrets.token_urlsafe(32)
            archive, _ = helper.create_backup(root, marker, ask=lambda **_: key)
            restored, _ = helper.restore_test(root, marker, ask=lambda **_: key)
            index = (archive.parent / 'last-restore.json').read_bytes()
            original = (root / 'data/candidate.sqlite3').read_bytes()
            with self.assertRaises(Exception):
                helper.restore_test(root, marker, ask=lambda **_: secrets.token_urlsafe(32))
            self.assertEqual(list(archive.parent.glob('restored-*')), [restored])
            self.assertEqual((archive.parent / 'last-restore.json').read_bytes(), index)
            self.assertEqual((root / 'data/candidate.sqlite3').read_bytes(), original)

    def test_tampered_archive_and_path_index_refused_before_prompt(self):
        with fixture() as (root, marker):
            key = secrets.token_urlsafe(32)
            archive, _ = helper.create_backup(root, marker, ask=lambda **_: key)
            payload = bytearray(archive.read_bytes())
            payload[-1] ^= 1
            archive.write_bytes(payload)
            ask = Mock()
            with self.assertRaises(helper.BackupError):
                helper.restore_test(root, marker, ask=ask)
            index = helper.state_read(archive.parent / 'last-backup.json')
            index['file'] = '../foreign.ppbk'
            helper.state_write(archive.parent / 'last-backup.json', index)
            with self.assertRaises(helper.BackupError):
                helper.restore_test(root, marker, ask=ask)
            ask.assert_not_called()
            self.assertEqual(list(archive.parent.glob('restored-*')), [])

    def test_foreign_backup_folder_keeps_existing_files(self):
        with fixture() as (root, marker):
            folder = root / 'backups-v17'
            folder.mkdir()
            keep = folder / 'keep.txt'
            keep.write_text('SYNTHETIC NOT OUR BACKUP FOLDER')
            with self.assertRaises(helper.BackupError):
                helper.backup_folder(root, marker, create=True)
            self.assertEqual(list(folder.iterdir()), [keep])

    def test_config_and_new_lifecycle_close_handles_even_on_validation_error(self):
        with fixture() as (root, marker):
            original_connect = sqlite3.connect
            connections = []
            def tracked(*args, **kwargs):
                connection = original_connect(*args, **kwargs)
                connections.append(connection)
                return connection
            with patch.object(runtime.sqlite3, 'connect', side_effect=tracked):
                runtime.read_config(root / 'data')
            self.assertEqual(len(connections), 2)
            for connection in connections:
                with self.assertRaises(sqlite3.ProgrammingError):
                    connection.execute('SELECT 1')
            connections.clear()
            with patch.object(runtime.sqlite3, 'connect', side_effect=tracked), patch.dict(runtime.REQUIRED, {'synthetic_missing': {'id'}}):
                with self.assertRaises(runtime.CandidateError):
                    runtime.read_config(root / 'data')
            self.assertEqual(len(connections), 1)
            with self.assertRaises(sqlite3.ProgrammingError):
                connections[0].execute('SELECT 1')
            connections.clear()
            fresh = root / 'synthetic-new-lifecycle'
            fresh.mkdir()
            instance = secrets.token_hex(16)
            with patch.object(runtime.sqlite3, 'connect', side_effect=tracked):
                runtime.create_lifecycle(fresh, instance)
            self.assertEqual(len(connections), 1)
            with self.assertRaises(sqlite3.ProgrammingError):
                connections[0].execute('SELECT 1')
            verify = original_connect(fresh / 'candidate-lifecycle.sqlite3')
            try:
                self.assertEqual(verify.execute('SELECT instance_id FROM lease_marker').fetchall(), [(instance,)])
            finally:
                verify.close()

    def test_restore_does_not_need_original_application_database(self):
        with fixture() as (root, marker):
            key = secrets.token_urlsafe(32)
            helper.create_backup(root, marker, ask=lambda **_: key)
            # Rename only this temporary synthetic test DB, never an installed one.
            (root / 'data/candidate.sqlite3').rename(root / 'data/synthetic-original-kept.sqlite3')
            restored, _ = helper.restore_test(root, marker, ask=lambda **_: key)
            self.assertTrue(runtime.read_config(restored)[1]['synthetic_only'])
            self.assertTrue((root / 'data/synthetic-original-kept.sqlite3').exists())

    def test_foreign_listener_refused_without_starting_or_stopping_process(self):
        with fixture() as (root, marker):
            key = secrets.token_urlsafe(32)
            helper.create_backup(root, marker, ask=lambda **_: key)
            helper.restore_test(root, marker, ask=lambda **_: key)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                with patch.object(helper, 'PORT', listener.getsockname()[1]), patch.object(helper.subprocess, 'Popen') as spawn:
                    with self.assertRaises(helper.BackupError):
                        helper.serve_restored(root, marker)
                    spawn.assert_not_called()

    def test_real_restored_http_keeps_branding_pdf_av_and_owner_isolation(self):
        import httpx
        class DrillComplete(Exception):
            pass
        with fixture() as (root, marker):
            data = root / 'data'
            payload = (data / 'files/synthetic-legacy.pdf').read_bytes()
            # Explicit synthetic AV fixture only, not real antivirus evidence.
            with sqlite3.connect(data / 'candidate.sqlite3') as db:
                db.execute("UPDATE center_settings SET center_name='SYNTHETIC RESTORE CENTER'")
                db.execute("INSERT INTO candidate_pdf_av_attestations (report_id,schema_version,sha256,verdict,source,scanned_at_utc) VALUES (1,1,?,'clean','clamd-instream-v1',?)",
                           (hashlib.sha256(payload).hexdigest(), datetime.now(timezone.utc).isoformat()))
            db.close()
            accounts = json.loads((data / 'synthetic-accounts.json').read_text())['accounts']
            key = secrets.token_urlsafe(32)
            helper.create_backup(root, marker, ask=lambda **_: key)
            restored, _ = helper.restore_test(root, marker, ask=lambda **_: key)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            url = f'http://127.0.0.1:{port}/login'
            original_popen = subprocess.Popen
            children = []
            commands = []
            def spawn(command, **kwargs):
                commands.append(command)
                child = original_popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
                children.append(child)
                return child
            def browser(opened_url):
                self.assertEqual(opened_url, url)
                for index in (1, 2):
                    with httpx.Client(base_url=url.rsplit('/', 1)[0], trust_env=False, timeout=10, follow_redirects=False) as client:
                        self.assertEqual(client.get('/login').status_code, 200)
                        account = accounts[index]
                        self.assertEqual(client.post('/login', data={'username': account['username'], 'password': account['password'],
                            'login_token': client.cookies.get('login_csrf')}).status_code, 303)
                        result = client.get('/reports/1/download')
                        self.assertEqual(result.status_code, 200 if index == 1 else 404)
                        if index == 1:
                            self.assertEqual(result.content, payload)
                            self.assertIn('SYNTHETIC RESTORE CENTER', client.get('/dashboard').text)
                raise DrillComplete()
            with patch.object(helper, 'PORT', port), patch.object(helper, 'URL', url), patch.object(helper.subprocess, 'Popen', side_effect=spawn):
                with self.assertRaises(DrillComplete):
                    helper.serve_restored(root, marker, browser=browser)
            self.assertTrue(all(child.poll() is not None for child in children))
            self.assertIn('--require-fresh-scanner', commands[0])
            self.assertIn(str(restored), commands[0])
            self.assertTrue((data / 'candidate.sqlite3').exists())


if __name__ == '__main__':
    original = subprocess.run([sys.executable, '-B', str(ROOT / 'tests/ft11/test_candidate_backup.py')], cwd=ROOT)
    if original.returncode:
        raise SystemExit(original.returncode)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
