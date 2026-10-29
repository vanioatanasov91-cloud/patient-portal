"""Pinned official scanner config and local Docker transport, no import-time work."""
import os
import re
import subprocess

IMAGE='clamav/clamav@sha256:bda39705e291105049c3936e2803ac90b955172af8030f94f05dce1252df6c6d'
CONF='''Foreground yes
TCPSocket 3310
TCPAddr 0.0.0.0
DatabaseDirectory /var/lib/clamav
TemporaryDirectory /tmp
PidFile /tmp/clamd.pid
LogFile /tmp/clamd.log
LogTime yes
LogClean no
LogVerbose no
ExtendedDetectionInfo no
StreamMaxLength 20M
MaxFileSize 20M
MaxScanSize 80M
MaxThreads 2
MaxQueue 4
ReadTimeout 10
CommandReadTimeout 10
SendBufTimeout 200
SelfCheck 0
ConcurrentDatabaseReload no
'''


class OwnedDockerError(RuntimeError):
    def __init__(self,operation,http_status=None):
        super().__init__('owned Docker operation failed: '+operation)
        self.http_status=http_status


def docker(*args,timeout=60):
    env={k:v for k,v in os.environ.items() if k not in
         {'DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH'}}
    result=subprocess.run(['docker','--host=unix:///var/run/docker.sock',*args],env=env,
                          capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        # Never retain raw output (it can contain proxy URLs). Only classify
        # explicit HTTP codes produced by the real updater for its report.
        output=result.stdout+'\n'+result.stderr
        match=re.search(r'(?:error code|HTTP(?:/[0-9.]+)?(?: code)?|response code)\s*[:=]?\s*(403|429)\b',output,re.I)
        raise OwnedDockerError(args[0],int(match[1]) if match else None)
    return result.stdout.strip()

