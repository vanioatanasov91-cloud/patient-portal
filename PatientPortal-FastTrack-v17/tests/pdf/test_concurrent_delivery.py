"""FT7 bounded synthetic concurrency smoke test, NOT a production/load benchmark.

Runs 16 contenders IN MEMORY with a copied candidate backend and fake ASGI send.
No HTTP server, production socket, deployed database, PDF data or Windows service.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import gc
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(Path(__file__).parent))
from test_pdf_hardening import safe_copy


def main():
    before=os.environ.copy()
    name='ft7_concurrency_fake_only'
    backend=None
    checks=0
    def check(ok, label):
        nonlocal checks
        if not ok:raise AssertionError(label)
        checks+=1
        print('PASS: '+label,flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix='FT7_CONCURRENT_FAKE_') as tmp:
            root=Path(tmp); appdir=root/'app';appdir.mkdir()
            safe_copy(appdir)
            os.environ.update({
                'PORTAL_ENV':'development',
                'PORTAL_SECRET':secrets.token_urlsafe(48),
                'DATABASE_URL':'sqlite:///'+(root/'fake.sqlite3').as_posix(),
                'PRIVATE_STORAGE':str(root/'uploads'),
                'PORTAL_PDF_SCAN_MODE':'off',
                'PORTAL_MAX_ACTIVE_PDF_DELIVERIES':'2',
            })
            spec=importlib.util.spec_from_file_location(name,appdir/'portal.py')
            assert spec and spec.loader
            backend=importlib.util.module_from_spec(spec)
            sys.modules[name]=backend
            spec.loader.exec_module(backend)
            check(backend.MAX_ACTIVE_PDF_DELIVERIES==2,'two concurrent in-process PDF responses maximum')
            payload=b'%PDF-1.4\n' + b'SYNTHETIC' * 512 + b'\nstartxref\n0\n%%EOF\n'
            checksum=hashlib.sha256(payload).hexdigest()
            backend.snapshot_verified_pdf=lambda doc:(payload,checksum)
            backend.log=lambda *args,**kwargs:None
            class StubDb:
                def commit(self):pass
            db=StubDb()
            doc=SimpleNamespace(id=77)
            start=threading.Barrier(16)
            gate=threading.Lock()
            active=0
            peak=0
            delivered=[]
            async def transmit(response):
                nonlocal active,peak
                collected=bytearray()
                async def receive():return {'type':'http.request','body':b'','more_body':False}
                async def send(message):
                    nonlocal active,peak
                    if message['type']=='http.response.body':
                        with gate:
                            active+=1;peak=max(peak,active)
                        try:
                            await asyncio.sleep(0.04)
                            collected.extend(message.get('body',b''))
                        finally:
                            with gate:active-=1
                await response({'type':'http','method':'GET','path':'/synthetic',
                                'headers':[]},receive,send)
                return bytes(collected)
            def contestant(_):
                start.wait(timeout=10)
                try:
                    result=backend.limited_pdf_delivery(doc,db=db,actor_id=1,action='test',inline=True)
                except backend.HTTPException as exc:
                    return ('reject',exc.status_code,exc.headers)
                return ('ok',asyncio.run(transmit(result)),None)
            with ThreadPoolExecutor(max_workers=16) as pool:
                outcomes=list(pool.map(contestant,range(16)))
            successes=[r for r in outcomes if r[0]=='ok']
            rejects=[r for r in outcomes if r[0]=='reject']
            check(len(successes)==2 and len(rejects)==14,
                  '16 simultaneous fake requests admit exactly two PDF responses')
            check(all(x[1]==payload for x in successes),'all accepted responses preserve exact synthetic bytes')
            check(all(r[1]==503 and r[2].get('Retry-After')=='2' for r in rejects),
                  'excess concurrent requests fail closed with Retry-After')
            check(0<peak<=2,'ASGI send concurrency never exceeds configured cap')
            check(backend._pdf_delivery_slots.acquire(blocking=False),
                  'first admission slot released after successful delivery')
            check(backend._pdf_delivery_slots.acquire(blocking=False),
                  'second admission slot released after successful delivery')
            check(not backend._pdf_delivery_slots.acquire(blocking=False),
                  'no third slot leaked into semaphore')
            backend._pdf_delivery_slots.release();backend._pdf_delivery_slots.release()
            check(len(backend.pdf_snapshot_response(payload,77,inline=False).body)==len(payload),
                  'synthetic PDF bytes remain bounded in memory response')
            # Validate exception cleanup without opening a network connection.
            response=backend.limited_pdf_delivery(doc,db=db,actor_id=1,action='test',inline=False)
            async def broken_send(_):raise RuntimeError('FAKE_ASGI_DISCONNECT')
            async def receive():return {'type':'http.request','body':b'','more_body':False}
            try:
                asyncio.run(response({'type':'http','method':'GET','path':'/fake',
                                      'headers':[]},receive,broken_send))
            except RuntimeError as exc:
                check(str(exc)=='FAKE_ASGI_DISCONNECT','simulated disconnected send propagates')
            else:raise AssertionError('Expected synthetic ASGI disconnect')
            permits=0
            while backend._pdf_delivery_slots.acquire(blocking=False):permits+=1
            check(permits==2,'cancelled/failed ASGI response releases its permit')
            for _ in range(permits):backend._pdf_delivery_slots.release()
            backend.engine.dispose()
            sys.modules.pop(name,None);backend=None
            gc.collect()
    finally:
        os.environ.clear();os.environ.update(before)
    print(f'PASS: FAST TRACK 7 SYNTHETIC CONCURRENCY ({checks} checks)')
    print('RELEASE GATE: HOLD / NO-GO. NOT A MULTIWORKER LOAD TEST.')


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('FAIL/HOLD: FT7 synthetic concurrent PDF delivery: '+type(exc).__name__,file=sys.stderr)
        raise SystemExit(1)
