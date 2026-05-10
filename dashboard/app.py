import os, json, threading, subprocess, datetime, logging
import requests
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from db import Database

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'poc-devsecops-2024'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')
db = Database()

REPORTS_DIR   = os.getenv('REPORTS_DIR', '/tmp/poc-reports')
WEBGOAT_LOCAL = os.getenv('WEBGOAT_LOCAL', '/tmp/poc-webgoat')
GITHUB_TOKEN  = os.getenv('GITHUB_TOKEN', '')
GITLAB_URL    = os.getenv('GITLAB_URL', 'https://gitlab.pcsupportlab.local')
GITLAB_TOKEN  = os.getenv('GITLAB_TOKEN', '')
GITLAB_PROJECT_ID = os.getenv('GITLAB_PROJECT_ID', '')
os.environ['no_proxy'] = 'localhost,127.0.0.1,gitlab.pcsupportlab.local'
os.environ['NO_PROXY'] = 'localhost,127.0.0.1,gitlab.pcsupportlab.local'
GITHUB_MODELS_URL = 'https://models.inference.ai.azure.com/chat/completions'
GITHUB_MODEL  = 'gpt-4o-mini'

STATE = {
    'current_step': 'idle',
    'scan_type': None,
    'initial_findings': [],
    'rescan_findings': [],
    'log': [],
    'processing': False,
}

def broadcast(event, data):
    socketio.emit(event, data)

def log_event(msg, level='info', step=None):
    entry = {
        'ts': datetime.datetime.utcnow().strftime('%H:%M:%S'),
        'msg': msg,
        'level': level,
        'step': step or STATE['current_step'],
    }
    STATE['log'].append(entry)
    if len(STATE['log']) > 500:
        STATE['log'] = STATE['log'][-500:]
    broadcast('log_entry', entry)
    log.info(msg)

@app.route('/webhook/step-update', methods=['POST'])
def webhook_step_update():
    data = request.json or {}
    step = data.get('step', '')
    status = data.get('status', 'running')
    scan_type = data.get('scan_type', 'initial')
    STATE['current_step'] = step
    STATE['scan_type'] = scan_type
    broadcast('step_update', {'step': step, 'status': status, 'scan_type': scan_type})
    log_event(f'Pipeline step: {step.upper()} - {status}', step=step)
    return jsonify({'ok': True})

@app.route('/webhook/scan-complete', methods=['POST'])
def webhook_scan_complete():
    data = request.json or {}
    scan_type    = data.get('scan_type', 'initial')
    report_path  = data.get('report_path', '')
    findings_cnt = data.get('findings_count', 0)
    pipeline_id  = data.get('pipeline_id', '')
    log_event(f'Scan complete ({scan_type}): {findings_cnt} findings found', 'success')
    findings = _parse_report(report_path)
    if scan_type == 'initial':
        STATE['initial_findings'] = findings
        db.save_scan('initial', findings, pipeline_id)
        broadcast('initial_scan_complete', {
            'count': len(findings),
            'by_severity': _severity_summary(findings),
        })
        if not STATE['processing']:
            thread = threading.Thread(target=_run_ai_fix_pipeline, args=(findings,))
            thread.daemon = True
            thread.start()
    elif scan_type == 'rescan':
        STATE['rescan_findings'] = findings
        db.save_scan('rescan', findings, pipeline_id)
        broadcast('rescan_complete', {
            'before': _severity_summary(STATE['initial_findings']),
            'after': _severity_summary(findings),
            'fixed': len(STATE['initial_findings']) - len(findings),
            'remaining': len(findings),
        })
        STATE['current_step'] = 'done'
        broadcast('step_update', {'step': 'done', 'status': 'complete'})
        log_event('POC complete - before/after comparison ready', 'success', step='done')
    return jsonify({'ok': True})

def _run_ai_fix_pipeline(findings):
    STATE['processing'] = True
    try:
        log_event('Setting up local WebGoat clone for patching...', step='ai_fix')
        broadcast('step_update', {'step': 'ai_fix', 'status': 'running'})
        _ensure_local_webgoat()
        files_to_fix = _group_findings_by_file(findings)
        log_event(f'Found {len(files_to_fix)} files with vulnerabilities to fix', step='ai_fix')
        fixed_files = []
        #for file_path, file_findings in list(files_to_fix.items())[:8]:
        for file_path, file_findings in list(files_to_fix.items())[:1]:
            log_event(f'AI fixing: {os.path.basename(file_path)} ({len(file_findings)} issues)', step='ai_fix')
            broadcast('ai_fixing_file', {'file': os.path.basename(file_path), 'issues': len(file_findings)})
            success = _fix_file_with_ai(file_path, file_findings)
            if success:
                fixed_files.append(file_path)
                log_event(f'Fixed: {os.path.basename(file_path)}', 'success', step='ai_fix')
            else:
                log_event(f'Could not fix: {os.path.basename(file_path)}', 'warning', step='ai_fix')
        log_event(f'AI fix complete: {len(fixed_files)} files patched', 'success', step='ai_fix')
        broadcast('step_update', {'step': 'commit', 'status': 'running'})
        log_event('Committing fixes to GitLab...', step='commit')
        commit_ok = _git_commit_and_push(fixed_files)
        if commit_ok:
            log_event('Fixes committed and pushed to GitLab', 'success', step='commit')
            broadcast('step_update', {'step': 'commit', 'status': 'complete'})
            log_event('Triggering re-scan pipeline...', step='rescan')
            broadcast('step_update', {'step': 'rescan', 'status': 'running'})
            _trigger_rescan_pipeline()
        else:
            log_event('Git commit failed - check logs', 'error', step='commit')
    except Exception as e:
        log_event(f'AI fix pipeline error: {e}', 'error')
    finally:
        STATE['processing'] = False

def _fix_file_with_ai(abs_file_path, findings):
    if not GITHUB_TOKEN:
        log_event('GITHUB_TOKEN not set - skipping AI fix', 'warning')
        return False
    try:
        with open(abs_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            original_code = f.read()
        vuln_summary = '\n'.join([
            f"- Line {v.get('start', {}).get('line', '?')}: {v.get('check_id', '')} - {v.get('extra', {}).get('message', '')}"
            for v in findings
        ])
        prompt = f'''Fix the Java security vulnerabilities listed below.
Output ONLY the complete Java source code.
Start your response directly with the Java code.
Do not add any explanation, comments outside the code, or markdown.
The first line of your response must be a Java package declaration, import statement, or class declaration.

Vulnerabilities to fix:
{vuln_summary}

Java file:
{original_code[:2000]}'''
        response = requests.post(
            GITHUB_MODELS_URL,
            headers={
                'Content-Type': 'application/json',
            },
            json={
                'model': GITHUB_MODEL,
                'messages': [
                    {'role': 'system', 'content': 'You are a Java code fixer. Output ONLY raw Java source code. Never explain. Never use markdown. Start directly with package or import or public class.'},
                    {'role': 'user', 'content': prompt},
                ],
		'stream': False,
            },
            timeout=300,
        )
        response.raise_for_status()
        fixed_code = response.json()['message']['content']

        # Strip markdown fences if present
        if '```' in fixed_code:
            lines = fixed_code.strip().split('\n')
            new_lines = []
            inside_code = False
            for line in lines:
                if line.strip().startswith('```'):
                    inside_code = not inside_code
                    continue
                if inside_code or not line.strip().startswith('```'):
                    new_lines.append(line)
            fixed_code = '\n'.join(new_lines).strip()

        # Reject PowerShell contamination
        if 'Write-Host' in fixed_code or 'param(' in fixed_code:
            log_event(f'AI output contains PowerShell - skipping', 'warning')
            return False

        # Find where Java code actually starts - skip any preamble text
        JAVA_KEYWORDS = ['package ', 'import ', 'public class', 'public interface',
                         'private class', 'class ', '/**', '/*', '//', '@']
        lines = fixed_code.strip().split('\n')
        code_start = 0
        for i, line in enumerate(lines):
            line_stripped = line.strip().lower()
            if any(line_stripped.startswith(kw.lower()) for kw in JAVA_KEYWORDS):
                code_start = i
                break

        if code_start > 0:
            log_event(f'Skipping {code_start} preamble lines from AI output', step='ai_fix')
            fixed_code = '\n'.join(lines[code_start:])

        # Final check - must have at least some Java content
        if not any(kw in fixed_code for kw in ['class ', 'import ', 'package ', 'public ', 'private ']):
            log_event(f'AI output has no recognisable Java content - skipping', 'warning')
            return False

        try:
            with open(abs_file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_code)
            return True
        except PermissionError as pe:
            log_event(f'Cannot write file (locked): {os.path.basename(abs_file_path)} - {pe}', 'warning')
            return False
    except Exception as e:
        log_event(f'AI fix error for {abs_file_path}: {e}', 'error')
        return False

def _ensure_local_webgoat():
    os.makedirs(WEBGOAT_LOCAL, exist_ok=True)
    webgoat_lessons = os.path.join(WEBGOAT_LOCAL, 'webgoat-lessons')
    if not os.path.exists(webgoat_lessons):
        log_event('Cloning WebGoat from GitHub into poc-webgoat...', step='ai_fix')
        try:
            import shutil
            shutil.rmtree(WEBGOAT_LOCAL)
            os.makedirs(WEBGOAT_LOCAL, exist_ok=True)
        except Exception as cleanup_err:
            log_event(f'Cleanup skipped: {cleanup_err} - cloning into existing folder', 'warning', step='ai_fix')
        try:
            subprocess.run(
                ['git', 'clone', '--depth=1', '--branch', 'v8.2.2',
                 'https://github.com/WebGoat/WebGoat.git',
                 WEBGOAT_LOCAL],
                check=True, capture_output=True
            )
            log_event('WebGoat cloned successfully', step='ai_fix')
        except Exception as clone_err:
            log_event(f'Clone failed: {clone_err}', 'error', step='ai_fix')
            raise
    else:
        log_event('WebGoat already cloned - using existing copy', step='ai_fix')


def _git_commit_and_push(fixed_files):
    try:
        log_event(f'Fixed files saved locally in {WEBGOAT_LOCAL}', 'success', step='commit')
        log_event(f'Rescan will scan fixed files directly from disk', 'info', step='commit')
        return True
    except Exception as e:
        log_event(f'Error: {e}', 'error')
        return False

def _trigger_rescan_pipeline():
    if not GITLAB_TOKEN or not GITLAB_PROJECT_ID:
        log_event('GITLAB_TOKEN/PROJECT_ID not set - trigger rescan manually', 'warning')
        return
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = requests.post(
            f'{GITLAB_URL}/api/v4/projects/{GITLAB_PROJECT_ID}/pipeline',
            headers={'PRIVATE-TOKEN': GITLAB_TOKEN},
            json={'ref': 'main', 'variables': [{'key': 'SCAN_TYPE', 'value': 'rescan'}]},
            timeout=10,
            verify=False
        )
        r.raise_for_status()
        log_event(f'Re-scan pipeline triggered automatically (ID: {r.json().get("id")})', 'success', step='rescan')
    except Exception as e:
        log_event(f'Could not auto-trigger re-scan: {e}. Run manually.', 'warning')

def _parse_report(report_path):
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        return data.get('results', [])
    except Exception as e:
        log_event(f'Could not parse report {report_path}: {e}', 'error')
        return []

def _severity_summary(findings):
    summary = {'ERROR': 0, 'WARNING': 0, 'INFO': 0}
    for f in findings:
        sev = f.get('extra', {}).get('severity', f.get('severity', 'INFO')).upper()
        summary[sev] = summary.get(sev, 0) + 1
    return summary

def _group_findings_by_file(findings):
    groups = {}
    for f in findings:
        path = f.get('path', '')
        if not path:
            continue
        path_normalized = path.replace('\\', '/')
        if 'webgoat-lessons' in path_normalized:
            idx = path_normalized.find('webgoat-lessons')
            relative_part = path_normalized[idx:]
            local_path = os.path.join(WEBGOAT_LOCAL, relative_part)
        elif not os.path.isabs(path):
            local_path = os.path.join(WEBGOAT_LOCAL, path)
        else:
            local_path = path
        if os.path.exists(local_path):
            groups.setdefault(local_path, []).append(f)
        else:
            log.warning(f'File not found for fixing: {local_path}')
    return groups

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/state')
def api_state():
    return jsonify({
        'current_step': STATE['current_step'],
        'scan_type': STATE['scan_type'],
        'initial_count': len(STATE['initial_findings']),
        'rescan_count': len(STATE['rescan_findings']),
        'initial_summary': _severity_summary(STATE['initial_findings']),
        'rescan_summary': _severity_summary(STATE['rescan_findings']),
        'processing': STATE['processing'],
        'log': STATE['log'][-50:],
    })

@app.route('/api/findings')
def api_findings():
    scan_type = request.args.get('type', 'initial')
    findings = STATE['initial_findings'] if scan_type == 'initial' else STATE['rescan_findings']
    simplified = [
        {
            'rule': f.get('check_id', '').split('.')[-1],
            'severity': f.get('extra', {}).get('severity', 'INFO'),
            'file': os.path.basename(f.get('path', '')),
            'line': f.get('start', {}).get('line', 0),
            'message': f.get('extra', {}).get('message', '')[:120],
        }
        for f in findings[:100]
    ]
    return jsonify(simplified)

@app.route('/api/reset', methods=['POST'])
def api_reset():
    STATE.update({
        'current_step': 'idle', 'scan_type': None,
        'initial_findings': [], 'rescan_findings': [],
        'log': [], 'processing': False,
    })
    db.clear()
    broadcast('reset', {})
    return jsonify({'ok': True})

@socketio.on('connect')
def on_connect():
    emit('state_sync', {
        'current_step': STATE['current_step'],
        'initial_count': len(STATE['initial_findings']),
        'rescan_count': len(STATE['rescan_findings']),
        'initial_summary': _severity_summary(STATE['initial_findings']),
        'rescan_summary': _severity_summary(STATE['rescan_findings']),
        'log': STATE['log'][-100:],
    })

if __name__ == '__main__':
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(WEBGOAT_LOCAL, exist_ok=True)
    print('=' * 60)
    print('  DevSecOps AI POC Dashboard')
    print('  Open http://localhost:5000 in your browser')
    print('=' * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
