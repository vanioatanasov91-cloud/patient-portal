"""Owned temporary loopback server for FT9 only; no supplied URLs or patient data."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/ft8'))
sys.path.insert(0, str(ROOT / 'app'))
from fixtures import candidate, seed, pdf_bytes
from legacy_pdf_policy import install_synthetic_policy
from shared_pdf_admission import install_synthetic_admission


def generated_pdf(path, size, label):
    """ReportLab PDF padded with PDF comments before startxref; exact byte size."""
    original = pdf_bytes(label)
    offset = original.rfind(b'startxref')
    prefix, suffix = original[:offset], original[offset:]
    remaining = size - len(original)
    assert remaining >= 2
    block = (b'%' + b'SYNTHETIC' * 8 + b'\n') * 512
    with path.open('xb') as out:
        out.write(prefix)
        while remaining >= len(block):
            out.write(block); remaining -= len(block)
        # Every leftover comment is properly newline-terminated; offsets in the
        # original xref remain correct because padding is AFTER that xref.
        if remaining >= 2: out.write(b'%' + b'X' * (remaining-2) + b'\n')
        elif remaining: out.write(b'\n')
        out.write(suffix)
    assert path.stat().st_size == size
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
    return digest.hexdigest()


def set_control(root, **values):
    path = root/'synthetic-control.json'
    current = json.loads(path.read_text()) if path.exists() else {}
    current.update(values)
    staging = root/'synthetic-control.next'
    staging.write_text(json.dumps(current))
    staging.replace(path)


@contextmanager
def server_fixture():
    import httpx
    with candidate() as (p, root):
        docid, sessions = seed(p, pdf_bytes())
        policy = install_synthetic_policy(p, root)
        total, uploads = install_synthetic_admission(p,root,prepare=True)
        shutil.copyfile(ROOT/'app/shared_pdf_admission.py',root/'app/shared_pdf_admission.py')
        set_control(root, scan_delay=0.0, scan_result='clean', send_delay=0.0)
        with p.SessionLocal() as db:
            doc=db.get(p.Report,docid)
            policy.add_result(db,doc.id,hashlib.sha256((p.STORAGE/doc.stored_name).read_bytes()).hexdigest(),'clean')
            db.commit()
        worker = '''import asyncio
import json
import os
from pathlib import Path
import time
import portal
from legacy_pdf_policy import SyntheticAvPolicy
from shared_pdf_admission import install_synthetic_admission
root = Path(os.environ['FT9_SYNTHETIC_ROOT'])
portal.pdf_av_policy = SyntheticAvPolicy(root)
portal.PDF_SCAN_MODE = 'clamd'
def control(): return json.loads((root/'synthetic-control.json').read_text())
def mocked_scan(path):
    settings = control()
    time.sleep(settings['scan_delay'])
    if settings['scan_result'] != 'clean':
        raise portal.HTTPException(503, 'SYNTHETIC SCANNER OUTAGE', headers={'Retry-After':'30'})
    return True
portal.scan_pdf_for_malware = mocked_scan
install_synthetic_admission(portal,root)
async def app(scope,receive,send):
    async def tagged(message):
        if message['type'] == 'http.response.start':
            message = dict(message)
            message['headers'] = list(message.get('headers',[])) + [(b'x-synthetic-worker',str(os.getpid()).encode())]
        if message['type'] == 'http.response.body' and scope.get('path','').endswith(('/download','/view','/preview')):
            delay = control()['send_delay']
            if delay: await asyncio.sleep(delay)
        await send(message)
    await portal.app(scope,receive,tagged)
'''
        launcher = '''import inspect
from pathlib import Path
import uvicorn
from uvicorn.supervisors import Multiprocess
if __name__ == '__main__':
    config = uvicorn.Config('synthetic_worker:app',host='127.0.0.1',port=0,workers=2,
                           access_log=False,log_level='error',timeout_graceful_shutdown=5,
                           timeout_keep_alive=2,limit_concurrency=64)
    server = uvicorn.Server(config)
    sock = config.bind_socket()
    Path('synthetic-port.txt').write_text(str(sock.getsockname()[1]))
    options = {'target':server.run} if 'target' in inspect.signature(Multiprocess).parameters else {}
    Multiprocess(config,sockets=[sock],**options).run()
    sock.close()
'''
        (root/'app/synthetic_worker.py').write_text(worker)
        (root/'app/synthetic_launcher.py').write_text(launcher)
        p.engine.dispose()
        child_env=os.environ.copy()
        child_env.update(FT9_SYNTHETIC_ROOT=str(root),PYTHONDONTWRITEBYTECODE='1',PORTAL_MAX_ACTIVE_PDF_DELIVERIES='2')
        kwargs={'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP} if os.name=='nt' else {'start_new_session':True}
        with (root/'server.log').open('wb') as log:
            process=subprocess.Popen([sys.executable,'-B','synthetic_launcher.py'],cwd=root/'app',env=child_env,
                                     stdout=log,stderr=log,**kwargs)
            workers=set()
            try:
                deadline=time.monotonic()+25
                base=None
                while time.monotonic()<deadline:
                    if process.poll() is not None:
                        print((root/'server.log').read_text(errors='replace')[-3000:])
                        raise RuntimeError('generated server exited')
                    portfile=root/'app/synthetic-port.txt'
                    if portfile.is_file():
                        base=f'http://127.0.0.1:{int(portfile.read_text())}'
                        try:
                            with httpx.Client(trust_env=False,timeout=1) as c:
                                result=c.get(base+'/healthz')
                            if result.status_code==200: workers.add(int(result.headers['x-synthetic-worker']))
                        except httpx.HTTPError: pass
                        if len(workers)==2: break
                    time.sleep(0.025)
                else: raise RuntimeError('two synthetic workers not ready')
                yield p,root,base,workers,docid,sessions,total,uploads
            finally:
                if process.poll() is None:
                    process.send_signal(signal.CTRL_BREAK_EVENT if os.name=='nt' else signal.SIGTERM)
                    try: process.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        if os.name=='nt': subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,timeout=5)
                        else: os.killpg(process.pid,signal.SIGKILL)
                        process.wait(timeout=5)
                p.engine.dispose()
