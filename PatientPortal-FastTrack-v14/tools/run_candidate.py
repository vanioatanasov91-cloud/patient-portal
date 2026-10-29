"""FT11 ordinary local workflow; loopback only, new synthetic stores only."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'app'))
from candidate_runtime import initialize,read_config,CandidateError,acquire_lifecycle


def main():
    parser=argparse.ArgumentParser(description='Patient Portal synthetic candidate; HOLD / NO-GO')
    subs=parser.add_subparsers(dest='command',required=True)
    init=subs.add_parser('init',help='Create a NEW synthetic store outside the source directory')
    init.add_argument('--data-dir',required=True)
    init.add_argument('--confirm-synthetic-only',action='store_true',required=True)
    init.add_argument('--scanner-port',type=int,default=3310)
    serve=subs.add_parser('serve',help='Serve an existing candidate on 127.0.0.1 only')
    serve.add_argument('--data-dir',required=True)
    serve.add_argument('--port',type=int,default=8000)
    serve.add_argument('--workers',type=int,choices=(1,2),default=2)
    check=subs.add_parser('check',help='Read-only local configuration/schema check; no scanner/production approval')
    check.add_argument('--data-dir',required=True)
    args=parser.parse_args()
    try:
        if args.command=='init':
            root=initialize(args.data_dir,scanner_port=args.scanner_port)
            print('Създаден е изолиран кандидат. Само синтетични данни. HOLD / NO-GO.')
            print('Синтетичните акаунти са в: '+str(root/'synthetic-accounts.json'))
            return 0
        root,config=read_config(args.data_dir)
        from shared_pdf_admission import DiskSlotPool
        DiskSlotPool(root/'shared-admission/total',2)
        DiskSlotPool(root/'shared-admission/uploads',1)
        if args.command=='check':
            print(json.dumps({'candidate_schema':2,'synthetic_only':True,'pdf_slots':2,'upload_slots':1,
                              'scanner':'local clamd configured, not probed','release_gate':'HOLD / NO-GO'},ensure_ascii=False))
            return 0
        if not 1<=args.port<=65535:raise CandidateError('HOLD: invalid loopback HTTP port')
        os.environ['PORTAL_CANDIDATE_DIR']=str(root)
        import uvicorn
        lease=acquire_lifecycle(root,config['instance_id'])
        try:
            uvicorn.run('candidate_entry:app',host='127.0.0.1',port=args.port,workers=args.workers,
                        proxy_headers=False,access_log=False,timeout_graceful_shutdown=5,log_level='info')
        finally:lease.close()
        return 0
    except (CandidateError,FileExistsError,OSError,RuntimeError) as exc:
        # No SQL parameters, secret values, patient metadata or raw daemon output.
        print('HOLD: кандидатът не е инициализиран/стартиран ('+type(exc).__name__+'). Проверете новата data директория и указанията.',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
