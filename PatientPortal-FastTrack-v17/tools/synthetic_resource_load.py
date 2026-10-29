"""FT9 owned-only two-worker boundary, slow-scan, disconnect and bounded soak test.

No URL option. Uses only generated temporary PDFs/DB and a mocked scanner.
"""
from __future__ import annotations
import argparse
import asyncio
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests/ft9'))
from http_fixture import server_fixture, generated_pdf, set_control
from legacy_pdf_policy import SyntheticAvPolicy
from sqlalchemy import select, func

MiB=1024*1024


def resources(pid):
    try:
        rss=None
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'): rss=int(line.split()[1])*1024
        # Account for spaces in /proc/stat comm field before splitting fields.
        fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
        cpu=(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')
        return rss,cpu
    except (OSError,ValueError,IndexError): return None,None


def all_recovered(total, timeout=4):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        a=total.try_acquire();b=total.try_acquire()
        recovered=a is not None and b is not None
        if a:a.close()
        if b:b.close()
        if recovered:return True
        time.sleep(0.025)
    return False


def main():
    import httpx
    parser=argparse.ArgumentParser(description='Owned ephemeral synthetic server only; never accepts a target URL')
    parser.add_argument('--soak-seconds',type=int,default=30,choices=range(10,61),metavar='10..60')
    args=parser.parse_args()
    checks=0
    def check(ok,label):
        nonlocal checks
        assert ok,label
        checks+=1
        print('PASS: '+label,flush=True)
    with server_fixture() as (p,root,base,workers,smallid,sessions,total,uploads):
        check(len(workers)==2,'both shared-admission workers are serving the owned test server')
        before_cpu={pid:resources(pid)[1] for pid in workers}
        peak_rss={pid:0 for pid in workers}
        observations=[]
        all_statuses=Counter()
        started=time.monotonic()
        def sample():
            current=[]
            for pid in workers:
                rss,_=resources(pid)
                if rss is not None:
                    current.append(rss);peak_rss[pid]=max(peak_rss[pid],rss)
            if len(current)==2:observations.append(sum(current))
        def cookie(role): return {'Cookie':'portal_session='+sessions[role][0]}
        def form(): return {'csrf':sessions['staff'][1],'title':'Синтетичен граничен PDF',
                           'modality':'ЯМР','exam_date':'2020-01-01','confirm_owner':'yes'}
        policy=SyntheticAvPolicy(root)
        legacy=p.STORAGE/'large64.pdf'
        legacy_hash=generated_pdf(legacy,64*MiB,'SYNTHETIC LEGACY 64 MIB')
        large_upload=root/'upload15.pdf'
        upload_hash=generated_pdf(large_upload,15*MiB,'SYNTHETIC UPLOAD 15 MIB')
        oversized_upload=root/'upload15plus.pdf'
        generated_pdf(oversized_upload,15*MiB+1,'SYNTHETIC OVERSIZE UPLOAD')
        oversized=p.STORAGE/'large64plus.pdf'
        generated_pdf(oversized,64*MiB+1,'SYNTHETIC OVERSIZE LEGACY')
        with p.SessionLocal() as db:
            large_ids=[]
            for path,digest in [(legacy,legacy_hash),(oversized,None)]:
                doc=p.Report(patient_id=sessions['patient'][2],uploaded_by=sessions['staff'][2],
                             modality='ЯМР',title='СИНТЕТИЧЕН ГОЛЯМ PDF',exam_date=p.now().date(),
                             stored_name=path.name,original_name='synthetic.pdf',published_at=p.now(),file_sha256=digest)
                db.add(doc);db.flush();large_ids.append(doc.id)
                if digest:policy.add_result(db,doc.id,digest,'clean')
            db.commit()
        largeid,oversizeid=large_ids
        with httpx.Client(base_url=base,trust_env=False,timeout=15,follow_redirects=False) as client:
            # The same state held by the parent blocks both server workers,
            # including publish/scan/upload, BEFORE body parsing.
            a,b=total.try_acquire(),total.try_acquire()
            try:
                statuses=[client.get(f'/reports/{smallid}/download',headers=cookie('patient')).status_code]
                for action in ('publish','scan'):
                    statuses.append(client.post(f'/reports/{smallid}/{action}',headers=cookie('staff'),data=form()).status_code)
                statuses.append(client.post(f'/patients/{sessions["patient"][2]}/reports',headers=cookie('staff'),content=b'SYNTHETIC').status_code)
                check(statuses==[503]*4,'one shared pool rejects download/publish/scan/upload across HTTP workers')
                check(client.get('/healthz').status_code==200 and client.get('/dashboard',headers=cookie('patient')).status_code==200,
                      'health and authenticated dashboard remain available while PDF capacity is full')
            finally:a.close();b.close()
            u=uploads.try_acquire()
            try:
                r=client.post(f'/patients/{sessions["patient"][2]}/reports',headers=cookie('staff'),content=b'SYNTHETIC')
                check(r.status_code==503 and r.headers.get('retry-after')=='2','shared upload sublimit rejects before multipart parsing')
                check(client.get(f'/reports/{smallid}/download',headers=cookie('patient')).status_code==200,'upload sublimit leaves delivery capacity available')
            finally:u.close()
            with large_upload.open('rb') as stream:
                r=client.post(f'/patients/{sessions["patient"][2]}/reports',headers=cookie('staff'),data=form(),
                              files={'file':('synthetic15.pdf',stream,'application/pdf')})
            check(r.status_code==303,'exactly 15 MiB synthetic upload is accepted with mocked clean scanner')
            with p.SessionLocal() as db:
                doc=db.scalar(select(p.Report).order_by(p.Report.id.desc()))
                uploadedid=doc.id
                check(doc.file_sha256==upload_hash and doc.published_at is None,'large upload preserves SHA256 and remains a draft')
                count=db.scalar(select(func.count(p.Report.id)))
            with oversized_upload.open('rb') as stream:
                r=client.post(f'/patients/{sessions["patient"][2]}/reports',headers=cookie('staff'),data=form(),
                              files={'file':('synthetic15plus.pdf',stream,'application/pdf')})
            check(r.status_code==413,'15 MiB plus one byte upload is refused')
            # Declared oversize request: middleware can refuse without reading.
            r=client.post(f'/patients/{sessions["patient"][2]}/reports',headers={**cookie('staff'),'Content-Length':str(16*MiB)},
                          content=b'X'*(16*MiB))
            check(r.status_code==413,'whole multipart/body ingress cap refuses oversized request')
            with p.SessionLocal() as db:
                check(db.scalar(select(func.count(p.Report.id)))==count,'oversized uploads create no report rows')
            def stream_pdf(target,role,expected_hash,expected_size,route='download'):
                digest=hashlib.sha256();length=0
                with client.stream('GET',f'/reports/{target}/{route}',headers=cookie(role)) as response:
                    check(response.status_code==200,'authorized boundary PDF response starts successfully')
                    for chunk in response.iter_bytes(1024*1024):
                        digest.update(chunk);length+=len(chunk);sample()
                check(length==expected_size and digest.hexdigest()==expected_hash,'boundary PDF length and SHA256 exactly match generated fixture')
            stream_pdf(uploadedid,'staff',upload_hash,15*MiB,'preview')
            stream_pdf(largeid,'patient',legacy_hash,64*MiB)
            check(client.get(f'/reports/{oversizeid}/download',headers=cookie('patient')).status_code==409,
                  '64 MiB plus one byte legacy PDF fails closed')
            check(client.get(f'/reports/{largeid}/download',headers=cookie('other')).status_code==404,'cross-patient large PDF remains denied')

            set_control(root,send_delay=0.15)
            async def large_wave():
                async with httpx.AsyncClient(base_url=base,trust_env=False,timeout=15,
                                              limits=httpx.Limits(max_connections=8,max_keepalive_connections=0)) as c:
                    async def one():
                        digest=hashlib.sha256();length=0
                        async with c.stream('GET',f'/reports/{largeid}/download',headers=cookie('patient')) as response:
                            if response.status_code==503:
                                assert response.headers.get('retry-after')=='2'
                            else:
                                assert response.status_code==200
                                async for chunk in response.aiter_bytes(1024*1024):
                                    digest.update(chunk);length+=len(chunk);sample()
                                assert length==64*MiB and digest.hexdigest()==legacy_hash
                            return response.status_code
                    return await asyncio.gather(*(one() for _ in range(8)))
            large_statuses=asyncio.run(large_wave())
            check(200 in large_statuses and 503 in large_statuses,'eight simultaneous 64 MiB downloads exercise accepted and rejected paths')
            check(all_recovered(total),'all shared slots recover after large response wave')
            # Close HTTP stream after headers, before delayed large body is sent.
            with client.stream('GET',f'/reports/{largeid}/download',headers=cookie('patient')) as response:
                check(response.status_code==200,'disconnect fixture starts an authorized large response')
            check(all_recovered(total),'real HTTP disconnect releases shared capacity after inner send completes')
            set_control(root,send_delay=0.0,scan_delay=0.4)
            async def slow_scans():
                async with httpx.AsyncClient(base_url=base,trust_env=False,timeout=10) as c:
                    tasks=[asyncio.create_task(c.post(f'/reports/{smallid}/scan',headers=cookie('staff'),data=form())) for _ in range(2)]
                    deadline=time.monotonic()+3
                    occupied=False
                    while time.monotonic()<deadline:
                        lease=total.try_acquire()
                        if lease is None:occupied=True;break
                        lease.close();await asyncio.sleep(0.01)
                    assert occupied,'slow scans never held shared slots'
                    denied=await c.get(f'/reports/{smallid}/download',headers=cookie('patient'))
                    replies=await asyncio.gather(*tasks)
                    return denied,[r.status_code for r in replies]
            denied,scans=asyncio.run(slow_scans())
            check(denied.status_code==503 and scans==[303,303],'slow scanner work keeps both aggregate slots until completion')
            set_control(root,scan_delay=0.01,scan_result='outage')
            check(client.post(f'/reports/{smallid}/scan',headers=cookie('staff'),data=form()).status_code==503,'mocked scanner outage remains fail closed')
            check(client.get(f'/reports/{smallid}/download',headers=cookie('patient')).status_code==423,'failed rescan leaves legacy AV hold in force')
            set_control(root,scan_delay=0.0,scan_result='clean')
            check(client.post(f'/reports/{smallid}/scan',headers=cookie('staff'),data=form()).status_code==303,'explicit clean mocked rescan restores delivery')

        # Bounded sustained phase; tiny generated PDF so bandwidth does not make
        # the client or snapshot allocation itself the stress test bottleneck.
        set_control(root,send_delay=0.015)
        latencies={200:[],503:[]}
        small=(p.STORAGE/'synthetic.pdf').read_bytes()
        async def soak():
            deadline=time.monotonic()+args.soak_seconds
            async with httpx.AsyncClient(base_url=base,trust_env=False,timeout=10,
                                          limits=httpx.Limits(max_connections=12,max_keepalive_connections=0)) as c:
                async def user():
                    while time.monotonic()<deadline:
                        start=time.perf_counter()
                        r=await c.get(f'/reports/{smallid}/download',headers=cookie('patient'))
                        assert r.status_code in (200,503),f'unexpected synthetic soak status {r.status_code}'
                        if r.status_code==200:assert r.content==small
                        else:assert r.headers.get('retry-after')=='2'
                        latencies[r.status_code].append((time.perf_counter()-start)*1000)
                        all_statuses[r.status_code]+=1
                        sample()
                        await asyncio.sleep(0.05)
                await asyncio.gather(*(user() for _ in range(8)))
        print(f'RUNNING: bounded {args.soak_seconds}s synthetic soak with 8 HTTP clients',flush=True)
        soak_started=time.monotonic();asyncio.run(soak());soak_elapsed=time.monotonic()-soak_started
        check(all_statuses[200]>=20 and all_statuses[503]>0,'sustained mixed admission produces verified deliveries and bounded retry responses')
        check(all_recovered(total),'all aggregate slots recover after sustained phase')
        # No worker restart is allowed to mask a resource regression.
        with httpx.Client(base_url=base,trust_env=False,timeout=3) as c:
            seen=set()
            deadline=time.monotonic()+5
            while seen != workers and time.monotonic()<deadline:
                # One persistent TCP connection is pinned to one worker. Use
                # fresh connections when checking both shared-socket workers.
                seen.add(int(c.get('/healthz',headers={'Connection':'close'}).headers['x-synthetic-worker']))
                if seen-workers:break
        check(seen==workers,'same two worker processes remain healthy after boundaries and soak')
        sample()
        after_cpu={pid:resources(pid)[1] for pid in workers}
        cpu_seconds=sum(after_cpu[pid]-before_cpu[pid] for pid in workers) if all(
            before_cpu[pid] is not None and after_cpu[pid] is not None for pid in workers) else None
        aggregate_peak=max(observations) if observations else None
        memory_budget=1024*MiB
        if aggregate_peak is not None:
            check(aggregate_peak<=memory_budget,'sampled aggregate worker RSS stays within 1 GiB fixture budget')
        if cpu_seconds is not None:
            check(cpu_seconds<=args.soak_seconds*2+20,'worker CPU time stays within documented synthetic run budget')
        def stats(values):
            values=sorted(values)
            return {'count':len(values),'median':round(values[len(values)//2],2),
                    'p95':round(values[math.ceil(len(values)*0.95)-1],2),'max':round(max(values),2)} if values else None
        report={'mode':'OWNED LOOPBACK / GENERATED SYNTHETIC ONLY','workers':2,'global_pdf_slots':2,'upload_slots':1,
                'boundary_bytes':{'upload_accepted':15*MiB,'upload_rejected':15*MiB+1,
                                  'legacy_accepted':64*MiB,'legacy_rejected':64*MiB+1},
                'large_wave_status_counts':dict(Counter(large_statuses)),
                'soak':{'clients':8,'requested_seconds':args.soak_seconds,'elapsed_seconds':round(soak_elapsed,3),
                        'status_counts':dict(all_statuses),'latency_ms_by_status':{str(k):stats(v) for k,v in latencies.items()}},
                'resources':{'sampled_aggregate_worker_peak_rss_bytes':aggregate_peak,
                             'per_worker_peak_rss_bytes':sorted(peak_rss.values()) if observations else None,
                             'aggregate_rss_budget_bytes':memory_budget,'worker_cpu_seconds':round(cpu_seconds,3) if cpu_seconds is not None else None,
                             'worker_cpu_budget_seconds':args.soak_seconds*2+20,
                             'scope':'Linux /proc workers only, sampled; excludes parent, clients, scanner, proxy and kernel buffers'},
                'checks_passed':checks,'elapsed_seconds':round(time.monotonic()-started,3),
                'release_gate':'HOLD / NO-GO','production_approved':False,
                'limitations':['single-host local filesystem prototype, not NFS/SMB or multi-host admission',
                               'scanner is mocked; legacy attestations are synthetic fixtures',
                               '30s default bounded soak is not an hours-long capacity or production certification',
                               'RSS is sampled, not an enforced OS memory ceiling; Windows unverified',
                               'no real reverse proxy, rate limit, TLS or production install was changed']}
        (ROOT/'reports').mkdir(exist_ok=True)
        (ROOT/'reports/last_synthetic_resource_load.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
        print(json.dumps(report,ensure_ascii=False,indent=2),flush=True)
    print(f'PASS: FT9 RESOURCE HTTP ({checks} checks). HOLD / NO-GO.')
    return 0


if __name__=='__main__':raise SystemExit(main())
