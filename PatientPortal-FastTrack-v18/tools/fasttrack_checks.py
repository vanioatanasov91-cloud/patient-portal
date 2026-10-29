#!/usr/bin/env python3
"""Fast Track: source-only checks. Never imports the app or touches Windows services."""
import ast, datetime, hashlib, json, os, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
MF=ROOT/'MANIFEST_SHA256.json'
checks=[]
def checked(cond,label):
    checks.append({'check':label,'ok':bool(cond)})
    print(('PASS: ' if cond else 'FAIL: ')+label,flush=True)

def main():
    try:
        manifest=json.loads(MF.read_text(encoding='utf-8'))
        checked(len(manifest)>=30,'Curated source manifest present')
        for rel,sha in manifest.items():
            path=ROOT/rel
            verified=path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==sha
            checked(verified,'SHA256: '+rel)
        base=ROOT/'app'
        checked(hashlib.sha256((base/'portal.py').read_bytes()).hexdigest()==manifest['app/portal.py'],
                'Fast Track 18 candidate backend SHA256')
        expected_templates=13
        checked(len(list((base/'templates').glob('*.html')))==expected_templates,'13 HTML templates')
        checked((base/'static/style.css').is_file() and (base/'static/portal-ui.js').is_file(),'CSS and JS present')
        bad=[]
        for p in ROOT.rglob('*'):
            if not p.is_file():continue
            n=p.name.lower()
            if n in ('.env','.env.local') or n.endswith(('.pdf','.sqlite','.sqlite3','.db','.ppbk','.pfx','.p12','.pem','.key','.exe')) or 'private_data' in p.parts or 'uploads' in p.parts:
                bad.append(str(p.relative_to(ROOT)))
        checked(not bad,'No private DB/PDF/secret/archive or executables in bundle')
        for p in ROOT.rglob('*.py'):
            try:
                ast.parse(p.read_text(encoding='utf-8-sig'),filename=str(p))
            except Exception:
                checked(False,'Python syntax: '+str(p.relative_to(ROOT)))
            else:
                checked(True,'Python syntax: '+str(p.relative_to(ROOT)))
        checked((ROOT/'tests/pdf/test_pdf_hardening.py').is_file(),'Candidate PDF regression exists')
        checked((ROOT/'tests/pdf/test_snapshot_delivery.py').is_file(),'PDF response snapshot regression exists')
        checked((ROOT/'tests/pdf/test_delivery_admission.py').is_file(),'PDF delivery admission regression exists')
        checked((ROOT/'tests/pdf/test_clamd_scan_gate.py').is_file(),'Clamd scan gate fake-only regression exists')
        checked((ROOT/'tools/legacy_pdf_inventory.py').is_file(),'Read-only legacy PDF inventory tool exists')
        checked((ROOT/'tests/pdf/test_legacy_inventory.py').is_file(),'Legacy PDF inventory fake-only regression exists')
        checked((ROOT/'tests/pdf/test_concurrent_delivery.py').is_file(),'Synthetic concurrent delivery regression exists')
        checked((ROOT/'AGENTS.md').is_file() and (ROOT/'CODEX_START_HERE_BG.md').is_file(),
                'Codex handoff instructions bundled')
        checked(not any((ROOT/'tests'/kind/'fixture_source').exists() for kind in ('ui','security')),
                'No stale detached UI/security source fixtures')
    except Exception as exc:
        checked(False,'Unexpected verifier failure: '+type(exc).__name__)
    result={'name':'PatientPortal FastTrack static preflight','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pass':sum(c['ok'] for c in checks),'fail':sum(not c['ok'] for c in checks),'checks':checks,'release_gate':'HOLD / NO-GO','mode':'STATIC SOURCE ONLY - NOT SECURITY APPROVAL'}
    reports=ROOT/'reports'
    reports.mkdir(exist_ok=True)
    (reports/'last_static_check.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print('STATIC SUMMARY: {} PASS / {} FAIL'.format(result['pass'],result['fail']))
    print('RELEASE GATE: HOLD / NO-GO')
    return 1 if result['fail'] else 0
if __name__=='__main__':sys.exit(main())
