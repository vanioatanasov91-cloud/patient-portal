"""Normal ASGI entrypoint of the explicitly initialized synthetic candidate."""
import os
from candidate_runtime import build_app, read_config, CandidateError

path=os.environ.get('PORTAL_CANDIDATE_DIR')
if not path:
    raise CandidateError('HOLD: initialize a synthetic candidate and set PORTAL_CANDIDATE_DIR')
mode=os.environ.get('PORTAL_CANDIDATE_REQUIRE_FRESH_SCANNER','0')
if mode not in ('0','1'):
    raise CandidateError('HOLD: invalid scanner readiness mode')
check=None
if mode=='1':
    from scanner_readiness import PilotScannerCheck
    _,config=read_config(path)
    check=PilotScannerCheck(config['scanner_port'])
app=build_app(path,scanner_precheck=check)
