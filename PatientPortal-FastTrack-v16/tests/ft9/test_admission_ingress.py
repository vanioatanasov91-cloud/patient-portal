"""ASGI boundary tests: no body read on denial; actual counts; safe lease lifetime."""
import asyncio
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'app'))
from shared_pdf_admission import DiskSlotPool, SharedPdfAdmission, IngressLimits


async def main():
    checks = 0
    def check(ok, label):
        nonlocal checks
        assert ok, label
        checks += 1
        print('PASS: ' + label, flush=True)
    with tempfile.TemporaryDirectory(prefix='FT9_SYNTHETIC_INGRESS_') as tmp:
        root = Path(tmp)
        total = DiskSlotPool.prepare(root/'total', 2)
        uploads = DiskSlotPool.prepare(root/'uploads', 1)
        reads, calls = 0, 0
        output = []
        async def send(message): output.append(message)
        async def consume(scope, receive, send):
            nonlocal calls
            calls += 1
            try:
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect': return
                    if not message.get('more_body', False): break
            except Exception:
                # Model frameworks translating multipart receive errors into 400.
                await send({'type':'http.response.start', 'status':400, 'headers':[]})
                await send({'type':'http.response.body', 'body':b'parser error'})
                return
            await send({'type':'http.response.start', 'status':200, 'headers':[]})
            await send({'type':'http.response.body', 'body':b'synthetic'})
        wrapper = SharedPdfAdmission(consume,total,uploads,IngressLimits(10,0.02,0.03))
        def scope(path='/patients/1/reports', method='POST', headers=()):
            return {'type':'http','method':method,'path':path,'headers':list(headers)}
        async def no_read():
            raise AssertionError('body read before admission')
        def status():
            return [m['status'] for m in output if m['type']=='http.response.start']
        a,b = total.try_acquire(),total.try_acquire()
        for path,method in [('/patients/1/reports','POST'),('/reports/1/publish','POST'),
                            ('/reports/1/scan','POST'),('/reports/1/download','GET'),
                            ('/reports/+1/view','GET'),('/reports/1/preview','GET')]:
            output.clear()
            await wrapper(scope(path,method),no_read,send)
            check(status()==[503] and (b'retry-after',b'2') in output[0]['headers'], 'shared cap covers '+path)
        check(calls==0, 'saturated PDF requests never reach auth/parser/backend')
        a.close();b.close()
        lease=uploads.try_acquire()
        await wrapper(scope(),no_read,send)
        lease.close()
        a,b=total.try_acquire(),total.try_acquire()
        check(a is not None and b is not None, 'upload sublimit denial returns its aggregate lease')
        a.close();b.close()
        for headers,code in [([(b'content-length',b'11')],413),
                             ([(b'content-length',b'3'),(b'content-length',b'3')],400),
                             ([(b'content-length',b'-1')],400)]:
            output.clear(); await wrapper(scope(headers=headers),no_read,send)
            check(status()==[code], 'declared oversized/ambiguous body refused without reading')
        for action in ('scan','publish'):
            output.clear()
            await wrapper(scope(f'/reports/1/{action}',headers=[(b'content-length',b'65537')]),no_read,send)
            check(status()==[413], 'mutation form ingress cap prevents oversized '+action+' bodies')
        def body_reader(chunks, delay=0):
            values=iter(chunks)
            async def receive():
                nonlocal reads
                reads+=1
                if delay: await asyncio.sleep(delay)
                chunk=next(values)
                return {'type':'http.request','body':chunk,'more_body':True}
            return receive
        output.clear()
        await wrapper(scope(),body_reader([b'123456',b'789012']),send)
        check(status()==[413] and b'parser error' not in output[-1]['body'], 'chunked body counted and parser response replaced once with 413')
        output.clear()
        await wrapper(scope(headers=[(b'content-length',b'1')]),body_reader([b'12345678901']),send)
        check(status()==[413], 'understated Content-Length cannot bypass byte cap at ASGI boundary')
        output.clear()
        await wrapper(scope(),body_reader([b'x'],0.05),send)
        check(status()==[408], 'stalled upload times out and releases capacity')
        output.clear()
        await wrapper(scope(),body_reader([b'a']*8,0.009),send)
        check(status()==[408], 'slow trickle cannot extend absolute upload receive deadline')
        async def one(): return {'type':'http.request','body':b'1234','more_body':False}
        output.clear();await wrapper(scope(),one,send)
        check(status()==[200], 'valid bounded upload passes through')
        a,b=total.try_acquire(),total.try_acquire()
        output.clear();await wrapper(scope('/dashboard','GET'),one,send)
        check(status()==[200], 'PDF saturation does not reserve dashboard/login capacity')
        a.close();b.close()
        async def broken_send(_): raise OSError('SYNTHETIC DISCONNECT')
        try: await wrapper(scope('/reports/1/download','GET'),one,broken_send)
        except OSError: check(True,'send error propagates without hiding disconnect')
        else: raise AssertionError('disconnect hidden')
        entered,finish=asyncio.Event(),asyncio.Event()
        async def slow_endpoint(scope,receive,send):
            entered.set(); await finish.wait()
        single=DiskSlotPool.prepare(root/'single',1)
        slow=SharedPdfAdmission(slow_endpoint,single,uploads)
        request=asyncio.create_task(slow(scope('/reports/1/scan'),one,send))
        await entered.wait()
        request.cancel();await asyncio.sleep(0)
        check(single.try_acquire() is None and not request.done(), 'caller cancellation cannot release a slot while inner work remains active')
        request.cancel();await asyncio.sleep(0)
        check(single.try_acquire() is None, 'repeated cancellation keeps the active-operation lease')
        finish.set()
        try: await request
        except asyncio.CancelledError: check(True,'cancellation re-raised after inner work drains')
        else: raise AssertionError('cancellation swallowed')
        lease=single.try_acquire()
        check(lease is not None,'cancelled operation releases lease after completion')
        lease.close()
        a,b=total.try_acquire(),total.try_acquire()
        u=uploads.try_acquire()
        check(a is not None and b is not None and u is not None,'all aggregate/upload slots recovered after errors and timeouts')
        a.close();b.close();u.close()
        # Real FastAPI/Starlette multipart parser, not the stub above. A partial
        # file must close when receive fails, including on older Starlette APIs.
        import starlette.formparsers as parser
        from fastapi import FastAPI, File, UploadFile
        app=FastAPI()
        @app.post('/patients/{patient_id}/reports')
        async def upload(patient_id:int,file:UploadFile=File(...)):
            raise AssertionError('incomplete upload reached endpoint')
        actual=SharedPdfAdmission(app,total,uploads,IngressLimits(2048,0.02,1.0))
        original=parser.SpooledTemporaryFile
        created=[]
        def track(*args,**kwargs):
            file=original(*args,**kwargs);created.append(file);return file
        parser.SpooledTemporaryFile=track
        try:
            header=(b'--synthetic-boundary\r\nContent-Disposition: form-data; name="file"; filename="synthetic.pdf"\r\n'
                    b'Content-Type: application/pdf\r\n\r\n'+b'X'*1024)
            for mode,expected in [('overflow',413),('timeout',408),('disconnect',400)]:
                output.clear();created.clear();parts=0
                async def partial():
                    nonlocal parts
                    parts+=1
                    if parts==1:return {'type':'http.request','body':header,'more_body':True}
                    if mode=='overflow':return {'type':'http.request','body':b'X'*4096,'more_body':True}
                    if mode=='timeout':await asyncio.sleep(0.05)
                    return {'type':'http.disconnect'}
                actual_scope=scope(headers=[(b'content-type',b'multipart/form-data; boundary=synthetic-boundary')])
                actual_scope.update(http_version='1.1',scheme='https',query_string=b'',server=('testserver',443),client=('127.0.0.1',1))
                await actual(actual_scope,partial,send)
                check(status()==[expected], 'real multipart parser returns bounded '+mode+' outcome')
                check(bool(created) and all(file.closed for file in created), 'partial multipart spool files close on '+mode)
        finally:parser.SpooledTemporaryFile=original
        (root/'total/slot-0').unlink()
        output.clear();await wrapper(scope(),no_read,send)
        check(status()==[503], 'shared lock state failure returns 503 before consuming body')
    print(f'PASS: FT9 INGRESS/LIFETIME ({checks} checks). HOLD / NO-GO.')


if __name__ == '__main__': asyncio.run(main())
