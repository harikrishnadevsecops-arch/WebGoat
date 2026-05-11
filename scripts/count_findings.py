import json, sys, os

scan_type = os.environ.get('SCAN_TYPE', 'initial')
report_file = f'reports/{scan_type}_scan.json'

try:
    with open(report_file) as f:
        d = json.load(f)
    print(len(d.get('results', [])))
except:
    print(0)
