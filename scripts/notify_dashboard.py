import json, base64, urllib.request, os, sys

scan_type = os.environ.get('SCAN_TYPE', 'initial')
run_id = os.environ.get('GITHUB_RUN_ID', '')
findings_count = int(os.environ.get('FINDINGS_COUNT', '0'))
dashboard_url = os.environ.get('DASHBOARD_URL', '')

print(f'scan_type: {scan_type}')
print(f'findings_count: {findings_count}')
print(f'dashboard_url: {dashboard_url}')

report_file = f'reports/{scan_type}_scan.json'
print(f'Reading report: {report_file}')

try:
    with open(report_file, 'rb') as f:
        raw = f.read()
    content = base64.b64encode(raw).decode('utf-8')
    print(f'Report read OK: {len(raw)} bytes')
except Exception as e:
    print(f'Could not read report: {e}')
    content = base64.b64encode(b'{"results":[]}').decode('utf-8')

payload = json.dumps({
    'scan_type': scan_type,
    'pipeline_id': run_id,
    'findings_count': findings_count,
    'report_content': content
}).encode('utf-8')

print(f'Payload size: {len(payload)} bytes')

if not dashboard_url:
    print('ERROR: DASHBOARD_URL is empty!')
    sys.exit(1)

req = urllib.request.Request(
    f'{dashboard_url}/webhook/scan-complete',
    data=payload,
    headers={'Content-Type': 'application/json'},
    method='POST'
)
try:
    resp = urllib.request.urlopen(req, timeout=30)
    print(f'Dashboard notified: {resp.status}')
except Exception as e:
    print(f'Dashboard notification failed: {e}')
