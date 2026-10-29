"""Explicit operator-owned real ClamAV lab. Never accepts an external portal URL.

Pull an official immutable image separately. This command creates/stops/removes only
its own container/network and generated candidate stores. Signature-age failure
remains a failure, even when all functional exercises succeed. HOLD always stays.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
sys.path.insert(0,str(ROOT/'tests/ft10'))
from test_candidate_workflow import run_cli,serving,Fields
from clamd_preflight import probe,exchange,EICAR
from clamav_signature_update import update_snapshot, verify_databases, UpdateError
import candidate_backup

from clamav_runtime import IMAGE, CONF, docker, OwnedDockerError
REPORT=ROOT/'reports/last_real_clamav_check.json'


from synthetic_pdf import pdf_bytes, eicar_pdf


def free_port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def wait_scanner(port):
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:
        try:
            if exchange(port,b'PING')==b'PONG':return
        except (OSError,ValueError):pass
        time.sleep(0.25)
    raise RuntimeError('real scanner readiness timeout')


def main():
    parser=argparse.ArgumentParser(description='Own real scanner/candidate lab, synthetic only, no arbitrary URL')
    parser.add_argument('--confirm-isolated-real-scanner-test',action='store_true',required=True)
    parser.add_argument('--update-signatures',action='store_true',
                        help='Explicit official FreshClam update in a new temporary snapshot, then live 48h preflight')
    args=parser.parse_args()
    report_path=ROOT/'reports/last_signature_update.json' if args.update_signatures else REPORT
    checks=[];container=None;network=None
    report={'mode':'REAL CLAMAV / OWNED LINUX DOCKER LAB / SYNTHETIC ONLY','image':IMAGE,
            'release_gate':'HOLD / NO-GO','production_approved':False,'status':'FAIL/HOLD',
            'started_utc':datetime.now(timezone.utc).isoformat(),'preflight_executed':False,
            'signature_update':{'requested':args.update_signatures,'status':'NOT_ATTEMPTED','updated':False}}
    def check(ok,label):
        checks.append({'check':label,'passed':bool(ok)})
        print(('PASS: ' if ok else 'FAIL: ')+label,flush=True)
        if not ok:raise AssertionError(label)
    try:
        docker('image','inspect',IMAGE) # no automatic pull or hidden network install
        with tempfile.TemporaryDirectory(prefix='FT13_REAL_SCANNER_',dir='/workspace') as folder:
            root=Path(folder);conf=root/'clamd.conf';conf.write_text(CONF)
            database_directory=None
            if args.update_signatures:
                database_directory,update=update_snapshot(root,docker,IMAGE)
                report['signature_update']=update
                databases=update['after']
            else:
                databases=verify_databases(docker,IMAGE)
                report['signature_update']['status']='IMAGE_DATABASES_ONLY'
            for entry in databases:
                check(entry['verified'],'official '+entry['database']+' CVD digital signature verifies')
            report['databases']=databases
            suffix=secrets.token_hex(5);container='pp-ft12-clamd-'+suffix;network='pp-ft12-net-'+suffix
            docker('network','create',network)
            port=free_port();http_port=free_port()
            docker('run','-d','--name',container,'--network',network,'--publish',f'127.0.0.1:{port}:3310',
                   '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','1000:1000',
                   '--memory','2g','--cpus','2','--pids-limit','64','--log-driver','none','--no-healthcheck',
                   '--tmpfs','/tmp:rw,noexec,nosuid,size=128m,mode=1777',
                   '--mount',f'type=bind,src={conf},dst=/run/clamd-test.conf,readonly',
                   *(['--mount',f'type=bind,src={database_directory},dst=/var/lib/clamav,readonly'] if database_directory else []),
                   '-e','TZ=UTC',
                   '--entrypoint','/usr/sbin/clamd',IMAGE,'--config-file=/run/clamd-test.conf')
            print('RUNNING: real clamd loading signed databases',flush=True)
            wait_scanner(port)
            inspect=json.loads(docker('inspect',container))[0]
            bindings=inspect['NetworkSettings']['Ports']['3310/tcp']
            check(bindings==[{'HostIp':'127.0.0.1','HostPort':str(port)}],'scanner port published exclusively on host loopback')
            mounts=inspect['Mounts']
            expected={'/run/clamd-test.conf':str(conf)}
            if database_directory:expected['/var/lib/clamav']=str(database_directory)
            check(len(mounts)==len(expected) and all(not m['RW'] and expected.get(m['Destination'])==m['Source'] for m in mounts),
                  'scanner has only expected read-only config/signature mounts and no candidate database/document mounts')
            check(inspect['Config']['User']=='1000:1000' and inspect['HostConfig']['ReadonlyRootfs']
                  and inspect['HostConfig']['Memory']==2*1024**3 and inspect['HostConfig']['NanoCpus']==2*10**9,
                  'scanner runs non-root with read-only root and explicit 2 GiB / 2 CPU limits')
            report['preflight_executed']=True
            preflight=probe(port=port,signature_timezone='UTC');report['preflight']=preflight
            for key in ('ping','clean_control','eicar_rejected'):
                check(preflight['checks'][key],'real ClamAV operational '+key)
            report['scanner_version']=exchange(port,b'VERSION').decode('ascii')
            control=eicar_pdf()
            check(exchange(port,b'INSTREAM',control).endswith(b' FOUND'),'real scanner detects harmless EICAR embedded inside a complete PDF')
            data=root/'candidate';restored=root/'restored';archive=root/'candidate.ppbk'
            check(run_cli('init','--data-dir',str(data),'--scanner-port',str(port),'--confirm-synthetic-only').returncode==0,
                  'normal candidate initialized against owned real scanner')
            accounts=json.loads((data/'synthetic-accounts.json').read_text())['accounts']
            import httpx
            with httpx.Client(base_url=f'http://127.0.0.1:{http_port}',trust_env=False,timeout=15,follow_redirects=False) as staff, \
                 httpx.Client(base_url=f'http://127.0.0.1:{http_port}',trust_env=False,timeout=15,follow_redirects=False) as patient:
                with serving(data,http_port,root/'candidate.log'):
                    for client,account in ((staff,accounts[0]),(patient,accounts[1])):
                        client.get('/login');token=client.cookies.get('login_csrf')
                        check(client.post('/login',data={**{k:account[k] for k in ('username','password')},'login_token':token}).status_code==303,
                              'synthetic login succeeds with real scanner connected')
                    with sqlite3.connect(data/'candidate.sqlite3') as db:
                        legacyid,patientid=db.execute('SELECT id,patient_id FROM reports').fetchone()
                    fields=Fields();fields.feed(staff.get(f'/patients/{patientid}').text);csrf=fields.csrf
                    form={'csrf':csrf,'title':'Синтетичен AV тест','modality':'ЯМР','exam_date':'2020-01-01','confirm_owner':'yes'}
                    clean=pdf_bytes('SYNTHETIC REAL SCANNER CLEAN CONTROL')
                    def upload(body):return staff.post(f'/patients/{patientid}/reports',data=form,files={'file':('synthetic.pdf',body,'application/pdf')})
                    check(upload(clean).status_code==303,'real ClamAV clean PDF creates a normal candidate draft')
                    with sqlite3.connect(data/'candidate.sqlite3') as db:
                        docid=db.execute('SELECT MAX(id) FROM reports').fetchone()[0]
                        before_count=db.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
                    check(staff.get(f'/reports/{docid}/preview').content==clean,'real-scanned draft previews exact bytes')
                    check(staff.post(f'/reports/{docid}/publish',data=form).status_code==303 and
                          patient.get(f'/reports/{docid}/download').content==clean,'real-scanned document publishes and downloads to its owner')
                    stored_count=len(list((data/'files').glob('*.pdf')))
                    rejected=upload(control)
                    check(rejected.status_code==422,'embedded EICAR PDF is rejected by the actual upload antivirus gate')
                    check('Eicar' not in rejected.text and 'FOUND' not in rejected.text,'malware signature is not exposed in patient-facing error')
                    with sqlite3.connect(data/'candidate.sqlite3') as db:
                        check(db.execute('SELECT COUNT(*) FROM reports').fetchone()[0]==before_count and
                              len(list((data/'files').glob('*.pdf')))==stored_count,'EICAR rejection leaves no report or stored PDF')
                    scanner_log=docker('exec',container,'cat','/tmp/clamd.log')
                    check(all(value not in scanner_log for value in ('synthetic_staff','synthetic_patient','synthetic.pdf')),
                          'INSTREAM scanner log omits generated patient usernames and original document filename')
                    docker('stop','--time','5',container)
                    check(upload(pdf_bytes('SYNTHETIC SCANNER DOWN CONTROL')).status_code==503,'stopped real scanner blocks new ingestion')
                    check(len(list((data/'files').glob('*.pdf')))==stored_count,'scanner outage leaves no orphan PDF')
                    check(patient.get(f'/reports/{docid}/download').content==clean,'outage does not silently revoke previously attested published report')
                    docker('start',container);wait_scanner(port)
                    check(staff.post(f'/reports/{legacyid}/scan',data={'csrf':csrf}).status_code==303,'real scanner recovery permits explicit legacy rescan')
                    check(patient.get(f'/reports/{legacyid}/download').content==(data/'files/synthetic-legacy.pdf').read_bytes(),
                          'real-scanned legacy owner delivery recovers')
                key=secrets.token_urlsafe(32)
                candidate_backup.create(data,archive,key)
                candidate_backup.restore(archive,restored,key)
                with serving(restored,http_port,root/'restored.log'):
                    check(patient.get('/dashboard').status_code==200,'encrypted restore preserves pre-backup patient session')
                    check(patient.get(f'/reports/{docid}/download').content==clean,'restored candidate serves real-scanned PDF with durable AV evidence')
                    with sqlite3.connect(restored/'candidate.sqlite3') as db:
                        check(db.execute('PRAGMA integrity_check').fetchone()==('ok',),'restored real-scanner candidate SQLite integrity is valid')
            report['signature_age_passed']=bool(preflight['checks']['signature_age'])
            report['status']='PASS/HOLD' if report['signature_age_passed'] else 'FUNCTIONAL_PASS/FRESHNESS_HOLD'
    except UpdateError as exc:
        report['signature_update']={'requested':args.update_signatures,**exc.summary()}
        report['status']='UPDATE_BLOCKED/HOLD' if args.update_signatures and exc.stage in ('connectivity','freshclam') else 'FAIL/HOLD'
        report['signature_age_passed']=False
        print(report['status']+': '+exc.reason,flush=True)
    except Exception as exc:
        report['error_type']=type(exc).__name__
        print('FAIL/HOLD: real scanner lab '+type(exc).__name__,flush=True)
    finally:
        cleanup=True
        if container:
            try:docker('rm','-f','--volumes',container)
            except Exception:cleanup=False
        if network:
            try:docker('network','rm',network)
            except Exception:cleanup=False
        report.update(checks=checks,functional_passed=sum(x['passed'] for x in checks),cleanup_completed=cleanup,
                      finished_utc=datetime.now(timezone.utc).isoformat())
        if not cleanup:report['status']='FAIL/HOLD'
        report_path.parent.mkdir(exist_ok=True);report_path.write_text(json.dumps(report,ensure_ascii=False,indent=2))
        if args.update_signatures and report.get('preflight_executed'):
            REPORT.write_text(json.dumps(report,ensure_ascii=False,indent=2))
        print(json.dumps({k:report.get(k) for k in ('status','functional_passed','signature_age_passed','cleanup_completed','release_gate')},indent=2),flush=True)
    return 0 if report['status']=='PASS/HOLD' else 1


if __name__=='__main__':raise SystemExit(main())
