"""Original scanner checks plus portable package/config/update safety fixtures.

No Windows executable is run here. PE/CVD fixtures are explicitly synthetic;
mock sigtool metadata does not certify real binaries/databases.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import windows_clamav as scanner


def fake_pe():
    data = bytearray(160)
    data[:2] = b'MZ'
    data[60:64] = (128).to_bytes(4, 'little')
    data[128:134] = b'PE\0\0\x64\x86'
    return bytes(data)


def fake_package(extra=None):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as z:
        for name in ('clamd.exe', 'freshclam.exe', 'sigtool.exe'):
            z.writestr(scanner.PREFIX + '/' + name, fake_pe())
        z.writestr(scanner.PREFIX + '/certs/clamav.crt', b'SYNTHETIC PUBLIC CERT FIXTURE')
        z.writestr(scanner.PREFIX + '/COPYING.txt', b'SYNTHETIC LICENCE FIXTURE')
        z.writestr(scanner.PREFIX + '/debug.pdb', b'UNUSED DEBUG FIXTURE')
        if extra:
            z.writestr(extra, b'SYNTHETIC MALFORMED PATH')
    return data.getvalue()


def fake_databases(directory):
    directory.mkdir(parents=True)
    records = []
    for name in ('main', 'daily', 'bytecode'):
        data = b'SYNTHETIC CVD FIXTURE: ' + name.encode()
        path = directory / (name + '.cvd')
        path.write_bytes(data)
        records.append({'database': name, 'sha256': hashlib.sha256(data).hexdigest(), 'verified': True})
    return records


class Response(io.BytesIO):
    status = 200


class PortableScannerTests(unittest.TestCase):
    def test_download_checksum_failure_leaves_no_executable_or_partial(self):
        with tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
            root = Path(tmp)
            content = fake_package()
            opener = Mock()
            opener.open.return_value = Response(content)
            with self.assertRaises(scanner.ScannerError):
                scanner.download_package(root / 'package.zip', opener=opener, expected_size=len(content), expected_sha='0' * 64)
            self.assertEqual(list(root.iterdir()), [])

    def test_fixed_official_download_then_no_redownload_when_verified(self):
        with tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
            content = fake_package()
            opener = Mock()
            opener.open.return_value = Response(content)
            path = Path(tmp) / 'package.zip'
            digest = hashlib.sha256(content).hexdigest()
            scanner.download_package(path, opener=opener, expected_size=len(content), expected_sha=digest)
            scanner.download_package(path, opener=opener, expected_size=len(content), expected_sha=digest)
            self.assertEqual(opener.open.call_count, 1)
            self.assertEqual(opener.open.call_args.args[0], scanner.ASSET_URL)

    def test_zip_windows_traversal_reserved_ads_and_links_refused(self):
        for bad in ('../escape.exe', '/absolute.dll', 'C:/drive.dll', 'x\\escape.exe',
                    scanner.PREFIX + '/.. /escape.dll', scanner.PREFIX + '/CON.exe', scanner.PREFIX + '/file.dll:stream'):
            with self.subTest(path=bad), tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
                root = Path(tmp)
                archive = root / 'package.zip'
                archive.write_bytes(fake_package(bad))
                with self.assertRaises(scanner.ScannerError):
                    scanner.extract_runtime(archive, root / 'runtime')
                self.assertFalse((root / 'runtime').exists())
        with tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
            root = Path(tmp)
            archive = root / 'symlink.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                info = zipfile.ZipInfo(scanner.PREFIX + '/escape.dll')
                info.create_system = 3
                info.external_attr = (0o120777 << 16)
                z.writestr(info, '../escape')
            with self.assertRaises(scanner.ScannerError):
                scanner.extract_runtime(archive, root / 'runtime')

    def test_runtime_subset_keeps_tools_cert_licence_and_skips_debug(self):
        with tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
            root = Path(tmp)
            archive = root / 'package.zip'
            archive.write_bytes(fake_package())
            records = scanner.extract_runtime(archive, root / 'runtime')
            self.assertEqual(len(records), 5)
            self.assertFalse((root / 'runtime' / scanner.PREFIX / 'debug.pdb').exists())
            self.assertIn(scanner.PREFIX + '/certs/clamav.crt', records)
            self.assertIn(scanner.PREFIX + '/COPYING.txt', records)

    def test_vendor_redirect_never_downgrades_or_uses_other_host(self):
        for url in ('http://github.com/package.zip', 'https://unapproved.invalid/package.zip'):
            with self.subTest(url=url), self.assertRaises(scanner.ScannerError):
                scanner.VendorRedirect().redirect_request(None, None, 302, '', {}, url)

    def test_native_error_does_not_expose_captured_secret_or_select_ready(self):
        result = subprocess.CompletedProcess([], 47, stdout='SYNTHETIC_PRIVATE_PROXY', stderr='SYNTHETIC_PRIVATE_PROXY')
        with patch.object(scanner.subprocess, 'run', return_value=result):
            with self.assertRaises(scanner.ScannerError) as failure:
                scanner.native(Path('SYNTHETIC BIN'), 'freshclam.exe', [])
        self.assertNotIn('PRIVATE_PROXY', str(failure.exception))

    def test_config_loopback_stream_limits_explicit_dirs_and_utc(self):
        root = Path('/SYNTHETIC PATH WITH SPACE')
        config = scanner.clamd_config(root, root / 'bin', root / 'db')
        self.assertIn('TCPAddr 127.0.0.1\n', config)
        self.assertIn('TCPSocket 3310\n', config)
        self.assertIn('EnableShutdownCommand no\n', config)
        self.assertIn('AlertExceedsMax yes\n', config)
        self.assertIn('"/SYNTHETIC PATH WITH SPACE/db"', config)
        self.assertNotIn('TCPAddr 0.0.0.0', config)
        self.assertNotIn('User ', config)
        fresh = scanner.freshclam_config(root / 'bin', root / 'db')
        self.assertIn('ScriptedUpdates no', fresh)
        self.assertNotIn('NotifyClamd', fresh)
        with patch.dict(os.environ, {'HTTPS_PROXY': 'SYNTHETIC_PROXY'}):
            env = scanner.native_environment(root / 'bin')
        self.assertEqual(env['HTTPS_PROXY'], 'SYNTHETIC_PROXY')
        self.assertEqual(env['TZ'], 'UTC0')
        self.assertEqual(env['LC_ALL'], 'C')
        self.assertNotIn('CURL_CA_BUNDLE', {k: v for k, v in env.items() if k not in os.environ})

    def test_fixed_48h_daily_check_fails_closed(self):
        now = datetime(2026, 10, 29, 12, tzinfo=timezone.utc)
        for hours, expected in ((0, True), (-48, True), (-49, False), (1, False)):
            stamp = (now + timedelta(hours=hours)).strftime('%d %b %Y %H:%M %z')
            self.assertIs(scanner.fresh_records([{'database': 'daily', 'Build time': stamp}], now=now), expected)
        self.assertFalse(scanner.fresh_records([], now=now))

    def test_unknown_store_single_owner_and_inactive_check_no_probe(self):
        with tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
            root = Path(tmp)
            keep = root / 'keep.txt'
            keep.write_text('SYNTHETIC EXISTING FILE')
            with self.assertRaises(scanner.ScannerError):
                scanner.owned_root(root, create=True)
            self.assertEqual(list(root.iterdir()), [keep])
            owned, marker = scanner.owned_root(root / 'owned', create=True)
            with scanner.lease(owned, marker):
                with self.assertRaises(scanner.ScannerBusy):
                    with scanner.lease(owned, marker):
                        pass
            with patch.object(scanner, 'probe') as probe:
                self.assertFalse(scanner.check(owned, marker)['ready'])
                probe.assert_not_called()

    def test_failed_offline_update_preserves_previous_snapshot_and_refuses_fast_retry(self):
        with tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
            root, marker = scanner.owned_root(Path(tmp) / 'owned', create=True)
            relative = 'snapshots/' + 'a' * 32 + '/db'
            records = fake_databases(root / relative)
            marker.update(signature_dir=relative, databases=records, last_update_ok=True)
            scanner.write_json(root / 'scanner.json', marker)
            run = Mock(side_effect=scanner.ScannerError('SYNTHETIC UPDATE REFUSED'))
            with self.assertRaises(scanner.ScannerError):
                scanner.update_snapshot(root, marker, Path('SYNTHETIC BIN'), run=run)
            saved = json.loads((root / 'scanner.json').read_text())
            self.assertFalse(saved['last_update_ok'])
            self.assertEqual(saved['signature_dir'], relative)
            for item in records:
                self.assertEqual(scanner.sha256(root / relative / (item['database'] + '.cvd')), item['sha256'])
            run.reset_mock()
            with self.assertRaises(scanner.ScannerError):
                scanner.update_snapshot(root, marker, Path('SYNTHETIC BIN'), run=run)
            run.assert_not_called()

    def test_unsigned_cvd_verdict_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='FT16_SYNTHETIC_SCANNER_') as tmp:
            root = Path(tmp) / 'db'
            fake_databases(root)
            with self.assertRaises(scanner.ScannerError):
                scanner.database_records(Path('SYNTHETIC BIN'), root, run=lambda *a, **k: 'Verification FAILED.')

    def test_active_foreign_listener_is_refused(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            with self.assertRaises(scanner.ScannerError):
                scanner.free_port(listener.getsockname()[1])


if __name__ == '__main__':
    original = subprocess.run([sys.executable, '-B', str(ROOT / 'tests/ft12/test_scanner_operations.py')], cwd=ROOT)
    if original.returncode:
        raise SystemExit(original.returncode)
    unittest.main(argv=[sys.argv[0]], verbosity=2)
