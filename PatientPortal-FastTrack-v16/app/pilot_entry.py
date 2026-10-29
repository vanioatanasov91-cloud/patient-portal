"""Shipping pilot ASGI entrypoint; only a marked synthetic pilot store."""
import os
from candidate_runtime import build_app
from pilot_runtime import read_pilot
from scanner_readiness import PilotScannerCheck

root, config = read_pilot(os.environ['PORTAL_PILOT_DIR'])
check = PilotScannerCheck(config['scanner_port'])
check()
app = build_app(root / 'candidate', scanner_precheck=check)
