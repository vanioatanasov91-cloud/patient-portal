"""Foreground Linux synthetic pilot. No OS services, public binds or real data.

An existing candidate/DB is never adopted or overwritten. Offline refresh switches
to a newly verified immutable snapshot. Only this supervisor's children and
labelled Docker resources can be stopped; no PID is read from disk.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'app'))
from candidate_runtime import (CandidateError, GATE, acquire_lifecycle,
                               initialize, private_write, read_config, root_path)
from scanner_readiness import scanner_ready
from clamav_runtime import IMAGE, CONF, docker
from clamav_signature_update import update_snapshot, verify_databases, validate_database_entries
from clamd_preflight import exchange, probe

KIND = 'PatientPortalSyntheticPilot'
LABEL = 'bg.patientportal.synthetic-pilot'


class PilotError(RuntimeError):
    pass


def supported():
    if sys.platform != 'linux' or os.getuid() != 1000:
        raise PilotError('Linux / UID1000 with the managed local Docker socket is required')
    if os.environ.get('PORTAL_ENV', '').lower() == 'production':
        raise PilotError('Synthetic pilot is forbidden in production mode')


def private_file(path):
    return (not path.is_symlink() and path.is_file() and path.stat().st_nlink == 1
            and path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0)


def write_marker(root, config):
    temporary = root / ('.pilot-next-' + secrets.token_hex(8))
    private_write(temporary, json.dumps(config, ensure_ascii=False, indent=2))
    temporary.replace(root / 'pilot.json')


def read_pilot(path, *, require_ready=True):
    supported()
    root = root_path(path)
    try:
        if (not root.is_dir() or root.stat().st_mode & 0o077 or root.stat().st_uid != os.getuid()
                or not private_file(root / 'pilot.json') or not private_file(root / 'pilot.lock')):
            raise ValueError()
        config = json.loads((root / 'pilot.json').read_text())
        if (config.get('kind') != KIND or config.get('version') != 1
                or config.get('synthetic_only') is not True or config.get('release_gate') != GATE
                or config.get('image') != IMAGE
                or not re.fullmatch(r'[0-9a-f]{32}', config.get('instance_id', ''))
                or any(type(config.get(k)) is not int or not 1024 <= config[k] <= 65535
                       for k in ('http_port', 'scanner_port'))
                or config['http_port'] == config['scanner_port']
                or config.get('state') not in ('awaiting_signatures', 'ready')
                or require_ready and config['state'] != 'ready'):
            raise ValueError()
        _, candidate = read_config(root / 'candidate')
        if candidate['scanner_port'] != config['scanner_port']:
            raise ValueError()
        if not private_file(root / 'clamd.conf') or (root / 'clamd.conf').read_text() != CONF:
            raise ValueError()
        if config['state'] == 'ready':
            relative = config.get('signature_dir', '')
            if not re.fullmatch(r'snapshots/[0-9a-f]{32}/updated-signatures', relative):
                raise ValueError()
            directory = root / relative
            if not directory.is_dir() or directory.is_symlink() or any(p.is_symlink() for p in directory.parents if p != root.parent):
                raise ValueError()
            validate_database_entries(directory)
            records = config.get('databases', [])
            if {r.get('database') for r in records} != {'main', 'daily', 'bytecode'} or len(records) != 3:
                raise ValueError()
            for record in records:
                path = directory / (record['database'] + '.cvd')
                if (record.get('verified') is not True or path.is_symlink() or not path.is_file()
                        or path.stat().st_nlink != 1):
                    raise ValueError()
                with path.open('rb') as handle:
                    if hashlib.file_digest(handle, 'sha256').hexdigest() != record['sha256']:
                        raise ValueError()
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise PilotError('Missing, incompatible or modified synthetic pilot state') from exc
    return root, config


@contextmanager
def exclusive(root):
    path = root / 'pilot.lock'
    if not private_file(path):
        raise PilotError('Missing pilot lock; never replace it while serving')
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PilotError('Pilot or offline maintenance is already active') from None
        yield
    finally:
        os.close(fd)


def refresh(path):
    root, config = read_pilot(path, require_ready=False)
    with exclusive(root):
        _, candidate = read_config(root / 'candidate')
        lease = acquire_lifecycle(root / 'candidate', candidate['instance_id'], exclusive=True)
        try:
            now = datetime.now(timezone.utc)
            if config.get('last_update_attempt_utc'):
                elapsed = now - datetime.fromisoformat(config['last_update_attempt_utc'])
                if elapsed < timedelta(hours=1):
                    raise PilotError('Wait at least one hour between official updater attempts')
            config['last_update_attempt_utc'] = now.isoformat()
            write_marker(root, config)
            docker('image', 'inspect', IMAGE)  # never auto-pull
            work = root / 'snapshots' / secrets.token_hex(16)
            work.mkdir(mode=0o700)
            directory, evidence = update_snapshot(work, docker, IMAGE)
            private_write(work / 'update-evidence.json', json.dumps(evidence, indent=2))
            config.update(state='ready', signature_dir=directory.relative_to(root).as_posix(),
                          databases=evidence['after'])
            write_marker(root, config)  # previous ready snapshot survives any earlier failure
        finally:
            lease.close()
    return root


def initialize_pilot(path, *, http_port=18080, scanner_port=13310):
    supported()
    root = root_path(path)
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in (http_port, scanner_port)) or http_port == scanner_port:
        raise PilotError('Two distinct unprivileged loopback ports are required')
    # Prevent accidentally creating state inside any earlier source release.
    if any((parent / 'AGENTS.md').exists() for parent in (root, *root.parents)):
        raise PilotError('Pilot state must be outside every source release')
    root.mkdir(mode=0o700)  # exclusive; no reset/reseed/adoption/migration
    private_write(root / 'pilot.lock', '0')
    private_write(root / 'clamd.conf', CONF)
    (root / 'snapshots').mkdir(mode=0o700)
    initialize(root / 'candidate', scanner_port=scanner_port)
    config = {'kind': KIND, 'version': 1, 'state': 'awaiting_signatures',
              'instance_id': secrets.token_hex(16), 'image': IMAGE,
              'synthetic_only': True, 'release_gate': GATE,
              'http_port': http_port, 'scanner_port': scanner_port}
    private_write(root / 'pilot.json', json.dumps(config, indent=2))
    refresh(root)
    return root


def resource_names(config):
    return 'pp-pilot-clamd-' + config['instance_id'], 'pp-pilot-net-' + config['instance_id']


def clean_owned(config):
    """Recover only exact labelled resources after a supervisor crash."""
    container, network = resource_names(config)
    for kind, name in (('container', container), ('network', network)):
        ids = docker(kind, 'ls', '-a', '--format', '{{.ID}}', '--filter', 'name=^/' + name + '$') if kind == 'container' else docker('network', 'ls', '--format', '{{.ID}}', '--filter', 'name=^' + name + '$')
        for identity in ids.splitlines():
            record = json.loads(docker(kind, 'inspect', identity))[0]
            labels = record['Config'].get('Labels', {}) if kind == 'container' else record.get('Labels', {})
            if labels.get(LABEL) != config['instance_id']:
                raise PilotError('Resource name collision; refuse unrelated resource')
            if kind == 'container':
                if record['Config']['Image'] != IMAGE:
                    raise PilotError('Owned scanner image mismatch')
                docker('rm', '-f', '--volumes', identity)
            else:
                docker('network', 'rm', identity)


def free_loopback(port):
    with socket.socket() as sock:
        # Match the listener's normal restart semantics. TIME_WAIT is not an
        # active service; a currently listening socket must still be refused.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))


def stop_child(process):
    if process is None:
        return
    # This new session/group was created by this supervisor, never from a PID file.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def http_ready(config):
    import httpx
    try:
        with httpx.Client(trust_env=False, timeout=2) as client:
            return client.get(f'http://127.0.0.1:{config["http_port"]}/login').status_code == 200
    except httpx.HTTPError:
        return False


def status(path):
    root, config = read_pilot(path)
    try:
        with exclusive(root):
            active = False
    except PilotError:
        active = True
    healthy = scanner_ready(config['scanner_port']) if active else False
    http = http_ready(config) if active else False
    return {'mode': 'LOCAL LINUX SYNTHETIC PILOT', 'supervisor_lock_held': active,
            'scanner_fresh': healthy, 'http_ready': http, 'ready': active and healthy and http,
            'url': f'http://127.0.0.1:{config["http_port"]}/login',
            'release_gate': GATE, 'production_approved': False}


def serve(path):
    root, config = read_pilot(path)
    child = None
    with exclusive(root):
        _, candidate = read_config(root / 'candidate')
        lease = acquire_lifecycle(root / 'candidate', candidate['instance_id'])
        try:
            clean_owned(config)
            free_loopback(config['http_port'])
            free_loopback(config['scanner_port'])
            verify_databases(docker, IMAGE, root / config['signature_dir'])
            container, network = resource_names(config)
            docker('network', 'create', '--label', LABEL + '=' + config['instance_id'], network)
            docker('run', '-d', '--name', container, '--label', LABEL + '=' + config['instance_id'],
                   '--network', network, '--publish', f'127.0.0.1:{config["scanner_port"]}:3310',
                   '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   '--user', '1000:1000', '--memory', '2g', '--cpus', '2', '--pids-limit', '64',
                   '--log-driver', 'none', '--no-healthcheck',
                   '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m,mode=1777',
                   '--mount', f'type=bind,src={root / "clamd.conf"},dst=/run/clamd-test.conf,readonly',
                   '--mount', f'type=bind,src={root / config["signature_dir"]},dst=/var/lib/clamav,readonly',
                   '-e', 'TZ=UTC', '--entrypoint', '/usr/sbin/clamd', IMAGE, '--config-file=/run/clamd-test.conf')
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                try:
                    if exchange(config['scanner_port'], b'PING') == b'PONG':
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.25)
            readiness = probe(port=config['scanner_port'], signature_timezone='UTC')
            if not readiness['protocol_passed']:
                raise PilotError('Scanner protocol/signature freshness preflight failed')
            record = json.loads(docker('inspect', container))[0]
            if (record['NetworkSettings']['Ports']['3310/tcp'] !=
                    [{'HostIp': '127.0.0.1', 'HostPort': str(config['scanner_port'])}]
                    or record['Config'].get('Labels', {}).get(LABEL) != config['instance_id']
                    or any(m['RW'] or m['Destination'] not in ('/run/clamd-test.conf', '/var/lib/clamav') for m in record['Mounts'])
                    or len(record['Mounts']) != 2):
                raise PilotError('Unexpected scanner exposure/mounts')
            log = root / 'pilot.log'
            if log.exists() and not private_file(log):
                raise PilotError('Pilot log must be a private regular file')
            fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'a') as output:
                child = subprocess.Popen([sys.executable, '-B', str(ROOT / 'tools/run_pilot.py'),
                                          '_http', '--pilot-dir', str(root)],
                                         stdout=output, stderr=output, start_new_session=True)
            deadline = time.monotonic() + 25
            while not http_ready(config):
                if child.poll() is not None or time.monotonic() > deadline:
                    raise PilotError('Pilot HTTP startup failed')
                time.sleep(0.2)
            print('Пилотът работи: ' + f'http://127.0.0.1:{config["http_port"]}/login', flush=True)
            print('Само синтетични данни. HOLD / NO-GO. Спиране: Ctrl+C.', flush=True)
            print('Акаунти (локален частен файл): ' + str(root / 'candidate/synthetic-accounts.json'), flush=True)
            while child.poll() is None:
                if not scanner_ready(config['scanner_port']):
                    raise PilotError('Scanner outage/stale signatures; pilot is stopping')
                time.sleep(5)
            raise PilotError('Pilot HTTP process exited')
        finally:
            try:
                stop_child(child)
            finally:
                try:
                    clean_owned(config)
                finally:
                    lease.close()


def serve_http(path):
    root, config = read_pilot(path)
    _, candidate = read_config(root / 'candidate')
    lease = acquire_lifecycle(root / 'candidate', candidate['instance_id'])
    os.environ['PORTAL_PILOT_DIR'] = str(root)
    try:
        import uvicorn
        uvicorn.run('pilot_entry:app', host='127.0.0.1', port=config['http_port'], workers=2,
                    proxy_headers=False, access_log=False, timeout_graceful_shutdown=5, log_level='info')
    finally:
        lease.close()
