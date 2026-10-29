"""Normal ASGI entrypoint of the explicitly initialized synthetic candidate."""
import os
from candidate_runtime import build_app, CandidateError

path=os.environ.get('PORTAL_CANDIDATE_DIR')
if not path:
    raise CandidateError('HOLD: initialize a synthetic candidate and set PORTAL_CANDIDATE_DIR')
app=build_app(path)
