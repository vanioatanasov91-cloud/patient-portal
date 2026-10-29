"""FT8 generated-only loopback HTTP stress smoke test, NEVER accepts a target URL.

Creates/disposes its own two-worker candidate server, SQLite and documents.
Mocked clean attestations are fixtures, never scanner/production evidence.
"""
from __future__ import annotations
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests' / 'ft8'))
sys.path.insert(0, str(ROOT / 'app'))
from fixtures import candidate, pdf_bytes, seed
from legacy_pdf_policy import install_synthetic_policy, SyntheticAvPolicy


def read_linux_rss(pid):
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'): return int(line.split()[1]) * 1024
    except (OSError, ValueError): pass
    return None


def main():
    import httpx
    checks = 0
    def check(ok, label):
        nonlocal checks
        assert ok, label
        checks += 1
        print('PASS: ' + label, flush=True)

    # Portable parent owns the listening socket; uvicorn's Multiprocess handles
    # joining worker processes on normal shutdown. Only this generated server.
    with candidate() as (p, root):
        payload = pdf_bytes('SYNTHETIC DOWNLOAD ' + 'X' * (128 * 1024), compress=False)
        docid, sessions = seed(p, payload)
        policy = install_synthetic_policy(p, root)
        with p.SessionLocal() as db:
            policy.add_result(db, docid, hashlib.sha256(payload).hexdigest(), 'clean')
            tokens = []
            # 24 distinct synthetic patient sessions + 8 staff upload sessions.
            for i in range(24):
                user = p.User(username=f'SYNTHETIC_LOAD_{i}', full_name='Синтетичен товарен пациент',
                              role='patient', password_hash='NOT_A_LOGIN', active=True)
                db.add(user); db.flush()
                token, csrf = p.make_session(db, user)
                # Each synthetic patient has its own same-byte report to check
                # authorization and avoid assigning another patient's record.
                doc = p.Report(patient_id=user.id, uploaded_by=sessions['staff'][2], modality='ЯМР',
                               title='Синтетичен товарен PDF', exam_date=p.now().date(),
                               stored_name=f'load_{i}.pdf', original_name='synthetic.pdf',
                               published_at=p.now(), file_sha256=hashlib.sha256(payload).hexdigest())
                (p.STORAGE / doc.stored_name).write_bytes(payload)
                db.add(doc); db.flush()
                policy.add_result(db, doc.id, doc.file_sha256, 'clean')
                tokens.append((token, doc.id))
            db.commit()
        # Stop retaining the initializer's DB pool before workers open SQLite.
        p.engine.dispose()
        worker_source = '''import os
from pathlib import Path
import portal
from legacy_pdf_policy import SyntheticAvPolicy
portal.pdf_av_policy = SyntheticAvPolicy(Path(os.environ['FT8_SYNTHETIC_ROOT']))

async def app(scope, receive, send):
    async def tagged(message):
        if message['type'] == 'http.response.start':
            message = dict(message)
            message['headers'] = list(message.get('headers', [])) + [(b'x-synthetic-worker', str(os.getpid()).encode())]
        await send(message)
    await portal.app(scope, receive, tagged)
'''
        (root / 'app' / 'synthetic_worker.py').write_text(worker_source)
        # A generated launcher keeps the reserved socket open across startup,
        # writes ONLY its chosen port, and closes/join children on shutdown.
        launcher = '''import inspect
import socket
from pathlib import Path
import uvicorn
from uvicorn.supervisors import Multiprocess
if __name__ == '__main__':
    config = uvicorn.Config('synthetic_worker:app', host='127.0.0.1', port=0, workers=2,
                            access_log=False, log_level='error', timeout_graceful_shutdown=5,
                            timeout_keep_alive=2, limit_concurrency=64)
    server = uvicorn.Server(config)
    sock = config.bind_socket()
    Path('synthetic-port.txt').write_text(str(sock.getsockname()[1]))
    options = {'target': server.run} if 'target' in inspect.signature(Multiprocess).parameters else {}
    Multiprocess(config, sockets=[sock], **options).run()
    sock.close()
'''
        (root / 'app' / 'synthetic_launcher.py').write_text(launcher)
        child_env = os.environ.copy()
        child_env.update(FT8_SYNTHETIC_ROOT=str(root), PYTHONDONTWRITEBYTECODE='1')
        stop = threading.Event()
        worker_pids = set()
        rss_peaks = {}
        def sample():
            while not stop.wait(0.02):
                for pid in tuple(worker_pids):
                    rss = read_linux_rss(pid)
                    if rss is not None: rss_peaks[pid] = max(rss_peaks.get(pid, 0), rss)
        sampler = threading.Thread(target=sample, daemon=True)
        kwargs = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
        with (root / 'server.log').open('wb') as log:
            server = subprocess.Popen([sys.executable, '-B', 'synthetic_launcher.py'], cwd=root / 'app',
                                      env=child_env, stdout=log, stderr=log, **kwargs)
            started = time.monotonic()
            latencies = []
            outcomes = []
            sampler.start()
            try:
                portfile = root / 'app' / 'synthetic-port.txt'
                deadline = time.monotonic() + 25
                base = None
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        print((root / 'server.log').read_text(errors='replace')[-4000:])
                        raise RuntimeError('generated test server exited')
                    if portfile.is_file():
                        base = f'http://127.0.0.1:{int(portfile.read_text())}'
                        try:
                            with httpx.Client(trust_env=False, timeout=1) as client:
                                r = client.get(base + '/healthz')
                            if r.status_code == 200:
                                worker_pids.add(int(r.headers['x-synthetic-worker']))
                                break
                        except (httpx.HTTPError, KeyError): pass
                    time.sleep(0.05)
                else: raise RuntimeError('generated test server did not become ready')
                # Fresh TCP connections allow the shared socket to reach both workers.
                deadline = time.monotonic() + 10
                while len(worker_pids) < 2 and time.monotonic() < deadline:
                    with httpx.Client(trust_env=False, timeout=2) as client:
                        r = client.get(base + '/healthz')
                    if r.status_code == 200: worker_pids.add(int(r.headers['x-synthetic-worker']))
                check(len(worker_pids) == 2, 'both isolated uvicorn workers responded')

                async def run_wave():
                    go = asyncio.Event()
                    async with httpx.AsyncClient(base_url=base, trust_env=False, timeout=20,
                                                 limits=httpx.Limits(max_connections=40, max_keepalive_connections=0)) as c:
                        async def request(index):
                            await go.wait()
                            start = time.perf_counter()
                            if index < 24:
                                token, target = tokens[index]
                                r = await c.get(f'/reports/{target}/download', headers={'Cookie':'portal_session=' + token})
                                expected = r.status_code == 200 and r.content == payload
                                kind = 'download'
                            else:
                                body = pdf_bytes(f'SYNTHETIC UPLOAD {index}')
                                r = await c.post(f'/patients/{sessions["patient"][2]}/reports',
                                    headers={'Cookie':'portal_session=' + sessions['staff'][0]},
                                    files={'file':(f'synthetic-{index}.pdf', body, 'application/pdf')},
                                    data={'csrf':sessions['staff'][1], 'title':f'Синтетичен PDF {index}',
                                          'modality':'ЯМР', 'exam_date':'2020-01-01', 'confirm_owner':'yes'})
                                expected = r.status_code == 303
                                kind = 'upload'
                            latencies.append((time.perf_counter() - start) * 1000)
                            worker_pids.add(int(r.headers['x-synthetic-worker']))
                            if r.status_code == 503:
                                expected = r.headers.get('retry-after') is not None
                            outcomes.append((kind, r.status_code, expected))
                        tasks = [asyncio.create_task(request(i)) for i in range(32)]
                        go.set()
                        await asyncio.gather(*tasks)
                asyncio.run(run_wave())
                check(len(outcomes) == 32 and all(ok for _, _, ok in outcomes), '32 mixed concurrent requests return valid responses or explicit admission retry')
                check(any(kind == 'download' and status == 200 for kind,status,_ in outcomes), 'real HTTP synthetic downloads completed with exact bytes')
                check(sum(kind == 'upload' and status == 303 for kind,status,_ in outcomes) == 8, 'eight concurrent synthetic uploads persisted as drafts')
                with httpx.Client(base_url=base, trust_env=False, timeout=5,
                                  headers={'Cookie':'portal_session=' + tokens[0][0]}) as c:
                    r = c.get(f'/reports/{tokens[0][1]}/download')
                    check(r.status_code == 200 and r.content == payload, 'PDF delivery recovers after the concurrent wave')
                    check(c.get(f'/reports/{docid}/download').status_code == 404, 'cross-patient access remains denied under HTTP')
                from sqlalchemy import select, func
                with p.SessionLocal() as db:
                    check(db.scalar(select(func.count(p.Report.id)).where(p.Report.published_at.is_(None))) == 8,
                          'all new uploads remain unpublished')
                # Fresh report on every successful execution, no stale result reuse.
                result = {'mode':'EPHEMERAL LOOPBACK / SYNTHETIC ONLY', 'workers_observed':len(worker_pids),
                          'clients':32, 'requests':len(outcomes),
                          'status_counts':dict(Counter(f'{kind}:{status}' for kind,status,_ in outcomes)),
                          'pdf_bytes':len(payload), 'latency_ms':{
                              'median':round(sorted(latencies)[len(latencies)//2],2),
                              'p95':round(sorted(latencies)[int(len(latencies)*0.95)-1],2),
                              'max':round(max(latencies),2)},
                          'worker_peak_rss_bytes': sorted(rss_peaks.values()) or None,
                          'rss_scope':'sampled Linux /proc per observed worker; excludes proxy/parent; not a memory bound',
                          'elapsed_seconds':round(time.monotonic()-started,3),
                          'release_gate':'HOLD / NO-GO', 'production_approved':False,
                          'limitations':['short synthetic smoke test, not capacity certification',
                                         'scanner OFF for uploads and seeded mocked attestations',
                                         'no shared admission limit or proxy ingress/spool protection',
                                         'single-host SQLite; not a distributed database benchmark']}
                (ROOT / 'reports').mkdir(exist_ok=True)
                (ROOT / 'reports' / 'last_synthetic_http_load.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
                print(json.dumps(result,ensure_ascii=False,indent=2), flush=True)
            finally:
                stop.set(); sampler.join(timeout=2)
                if server.poll() is None:
                    if os.name == 'nt': server.send_signal(signal.CTRL_BREAK_EVENT)
                    else: server.send_signal(signal.SIGTERM)
                    try: server.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        if os.name != 'nt': os.killpg(server.pid, signal.SIGKILL)
                        else:
                            subprocess.run(['taskkill', '/PID', str(server.pid), '/T', '/F'],
                                           check=False, capture_output=True, timeout=5)
                        server.wait(timeout=5)
                p.engine.dispose()
    print(f'PASS: FT8 MULTIWORKER HTTP ({checks} checks). HOLD / NO-GO.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
