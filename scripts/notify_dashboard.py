import json, base64, urllib.request, os, sys

scan_type = os.environ.get('SCAN_TYPE', 'initial')
run_id = os.environ.get('GITHUB_RUN_ID', '')
findings_count = int(os.environ.get('FINDINGS_COUNT', '0'))
dashboard_url = os.environ.get('DASHBOARD_URL', '')

report_file = f'reports/{scan_type}_scan.json'
try:
    with open(report_file, 'rb') as f:
        content = base64.b64encode(f.read()).decode('utf-8')
    print(f'Report file read successfully')
except Exception as e:
    print(f'Could not read report file: {e}')
    content = base64.b64encode(b'{"results":[]}').decode('utf-8')

payload = json.dumps({
    'scan_type': scan_type,
    'pipeline_id': run_id,
    'findings_count': findings_count,
    'report_content': content
}).encode('utf-8')

req = urllib.request.Request(
    f'{dashboard_url}/webhook/scan-complete',
    data=payload,
    headers={'Content-Type': 'application/json'},
    method='POST'
)
try:
    resp = urllib.request.urlopen(req, timeout=30)
    print(f'Dashboard notified successfully: {resp.status}')
except Exception as e:
    print(f'Dashboard notification failed: {e}')
