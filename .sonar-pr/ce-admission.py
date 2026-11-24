#!/usr/bin/env python3
"""Hold the designated scan runner until CE pending queue is below the configured limit.
Not an atomic distributed lock: all scan submissions must share one exclusive runner pool.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

host = os.environ['SONAR_HOST_URL'].rstrip('/')
token = os.environ['SONAR_TOKEN']
max_pending = int(os.getenv('CE_MAX_PENDING', '0'))
max_wait = int(os.getenv('CE_ADMISSION_TIMEOUT_SECONDS', '900'))
interval = int(os.getenv('CE_ADMISSION_POLL_SECONDS', '10'))
if max_pending < 0 or max_wait <= 0 or interval <= 0:
    raise ValueError('Invalid admission configuration')

deadline = time.monotonic() + max_wait
url = f'{host}/api/ce/activity_status'
while True:
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            status = json.load(response)
    except Exception as exc:
        print(f'CE admission check failed (fail-closed): {exc}', file=sys.stderr)
        sys.exit(2)
    # API returns summary counts as integers on supported SonarQube versions.
    pending = status.get('pending')
    in_progress = status.get('inProgress')
    if not isinstance(pending, int) or not isinstance(in_progress, int):
        print(f'Unexpected CE activity_status response: {status!r}', file=sys.stderr)
        sys.exit(2)
    print(f'CE pending={pending}, processing={in_progress}; allowed pending <= {max_pending}', flush=True)
    if pending <= max_pending:
        print('CE submission admitted', flush=True)
        sys.exit(0)
    if time.monotonic() + interval >= deadline:
        print('CE admission timeout: declining to submit additional analysis', file=sys.stderr)
        sys.exit(2)
    time.sleep(interval)
