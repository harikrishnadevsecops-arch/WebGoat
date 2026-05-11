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
GITHUB_REPO   = os.getenv('GITHUB_REPO', 'harikrishnadevsecops-arch/WebGoat')
GITHUB_TOKEN_API = os.getenv('GH_API_TOKEN', '')
os.environ['no_proxy'] = 'localhost,127.0.0.1'
os.environ['NO_PROXY'] = 'localhost,127.0.0.1'
GITHUB_MODELS_URL = 'https://models.inference.ai.azure.com/chat/completions'
GITHUB_MODEL  = 'gpt-4o-mini'

STATE = {
    'current_step': 'idle',
    'scan_type': None,
    'initial_findings': [],
    'rescan_findings': [],
    'log': [],
    'processing': False,
    'pending_pr': None,
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
    findings_cnt = data.get('findings_count', 0)
    pipeline_id  = data.get('pipeline_id', '')
    report_content = data.get('report_content', '')
 
    log_event(f'Scan complete ({scan_type}): {findings_cnt} findings found', 'success')
 
    # Parse findings from base64 encoded content
    findings = _parse_report_content(report_content)
 
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
        log_event('Committing fixes to GitHub...', step='commit')
        commit_ok = _git_commit_and_push(fixed_files)
        if commit_ok:
            log_event('Fixes committed and pushed to GitHub', 'success', step='commit')
            broadcast('step_update', {'step': 'commit', 'status': 'complete'})
            log_event('Waiting for PR Review and Approval before rescan...', 'info', step='rescan')
            broadcast('step_update', {'step': 'rescan', 'status': 'waiting'})
            #Comment: _trigger_rescan_pipeline()
        else:
            log_event('Git commit failed - check logs', 'error', step='commit')
    except Exception as e:
        log_event(f'AI fix pipeline error: {e}', 'error')
    finally:
        STATE['processing'] = False

def _fix_file_with_ai(abs_file_path, findings):
    if not GITHUB_TOKEN_API:
        log_event('GITHUB_TOKEN_API not set - skipping AI fix', 'warning')
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
                'Authorization': f'Bearer {GITHUB_TOKEN_API}',
                'Content-Type': 'application/json',
            },
            json={
                'model': GITHUB_MODEL,
                'messages': [
                    {'role': 'system', 'content': 'You are a Java security expert. Return only valid Java code. Start directly with package or import or public class. Never explain. Never use markdown.'},
                    {'role': 'user', 'content': prompt},
                ],
                'temperature': 0.1,
                'max_tokens': 4000,
            },
            timeout=60,
        )
        response.raise_for_status()
        fixed_code = response.json()['choices'][0]['message']['content']


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
    git_dir = os.path.join(WEBGOAT_LOCAL, '.git')
    if not os.path.exists(git_dir):
        log_event('Cloning WebGoat from GitHub fork...', step='ai_fix')
        try:
            import shutil
            shutil.rmtree(WEBGOAT_LOCAL)
            os.makedirs(WEBGOAT_LOCAL, exist_ok=True)
        except Exception as e:
            log_event(f'Cleanup skipped: {e}', 'warning', step='ai_fix')
        try:
            clone_url = f'https://{GITHUB_TOKEN_API}@github.com/{GITHUB_REPO}.git'
            subprocess.run(
                ['git', 'clone', '--depth=1', clone_url, WEBGOAT_LOCAL],
                check=True, capture_output=True
            )
            log_event('WebGoat fork cloned successfully', step='ai_fix')
        except Exception as e:
            log_event(f'Clone failed: {e}', 'error', step='ai_fix')
            raise
    else:
        log_event('WebGoat already cloned - using existing copy', step='ai_fix')


def _git_commit_and_push(fixed_files):
    try:
        import time
        branch_name = f'ai-fix-{int(time.time())}'
 
        subprocess.run(['git', 'config', 'user.email', 'ai-agent@devsecops.poc'],
                      cwd=WEBGOAT_LOCAL, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'AI Security Agent'],
                      cwd=WEBGOAT_LOCAL, capture_output=True)
 
        # Create new branch
        subprocess.run(['git', 'checkout', '-b', branch_name],
                      cwd=WEBGOAT_LOCAL, check=True, capture_output=True)
 
        for f in fixed_files:
            rel = os.path.relpath(f, WEBGOAT_LOCAL)
            subprocess.run(['git', 'add', rel], cwd=WEBGOAT_LOCAL, capture_output=True)
 
        status = subprocess.run(['git', 'status', '--porcelain'],
                               cwd=WEBGOAT_LOCAL, capture_output=True, text=True)
        if not status.stdout.strip():
            log_event('No changes to commit', 'warning', step='commit')
            return True
 
        msg = f'[AI-Fix] Auto-remediated {len(fixed_files)} vulnerable files'
        subprocess.run(['git', 'commit', '-m', msg],
                      cwd=WEBGOAT_LOCAL, check=True, capture_output=True)
 
        remote_url = f'https://{GITHUB_TOKEN_API}@github.com/{GITHUB_REPO}.git'
        subprocess.run(['git', 'remote', 'set-url', 'origin', remote_url],
                      cwd=WEBGOAT_LOCAL, capture_output=True)
        subprocess.run(['git', 'push', 'origin', branch_name],
                      cwd=WEBGOAT_LOCAL, check=True, capture_output=True)
 
        log_event(f'Fixed files pushed to branch: {branch_name}', 'success', step='commit')
 
        # Create Pull Request
        _create_pull_request(branch_name, len(fixed_files))
        return True
 
    except subprocess.CalledProcessError as e:
        log_event(f'Git error: {e}', 'error')
        return False


def _create_pull_request(branch_name, files_fixed):
    try:
        pr_body = f"""## AI Security Fix — Automated Vulnerability Remediation
 
### Summary
This Pull Request was automatically created by the DevSecOps AI Agent.
 
- **Files fixed:** {files_fixed}
- **AI Model:** GitHub Models API (gpt-4o-mini)
- **Branch:** {branch_name}
 
### What was fixed
The AI agent analysed the Semgrep SAST scan report and automatically remediated the identified vulnerabilities.
 
### Review checklist
- [ ] Review each changed file carefully
- [ ] Verify the fix addresses the vulnerability correctly
- [ ] Ensure no new issues were introduced
- [ ] Approve and merge to trigger automatic re-scan
 
> ⚠️ Please review all changes before merging. The re-scan will run automatically after merge.
"""
        r = requests.post(
            f'https://api.github.com/repos/{GITHUB_REPO}/pulls',
            headers={
                'Authorization': f'Bearer {GITHUB_TOKEN_API}',
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json'
            },
            json={
                'title': f'[AI-Fix] Automated security vulnerability remediation',
                'body': pr_body,
                'head': branch_name,
                'base': 'main'
            },
            timeout=30
        )
        if r.status_code == 201:
            pr_url = r.json().get('html_url', '')
            pr_number = r.json().get('number', '')
            STATE['pending_pr'] = {'url': pr_url, 'number': pr_number, 'branch': branch_name}
            log_event(f'Pull Request created: {pr_url}', 'success', step='commit')
            broadcast('pr_created', {'url': pr_url, 'number': pr_number, 'branch': branch_name})
            log_event('Waiting for PR review and approval...', 'info', step='rescan')
            broadcast('step_update', {'step': 'rescan', 'status': 'waiting'})
        else:
            log_event(f'PR creation failed: {r.status_code} {r.text[:200]}', 'error')
    except Exception as e:
        log_event(f'Could not create PR: {e}', 'error')



def _trigger_rescan_pipeline():
    if not GITHUB_TOKEN_API:
        log_event('GITHUB_TOKEN_API not set - trigger rescan manually', 'warning')
        return
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = requests.post(
            f'https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/devsecops-pipeline.yml/dispatches',
            headers={
                'Authorization': f'Bearer {GITHUB_TOKEN_API}',
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json'
            },
            json={
                'ref': 'main',
                'inputs': {'scan_type': 'rescan'}
            },
            timeout=10
        )
        if r.status_code == 204:
            log_event('Re-scan pipeline triggered automatically', 'success', step='rescan')
        else:
            log_event(f'Could not trigger re-scan: {r.status_code} {r.text}', 'warning')
    except Exception as e:
        log_event(f'Could not auto-trigger re-scan: {e}. Run manually.', 'warning')


def _parse_report_content(report_content):
    try:
        import base64
        decoded = base64.b64decode(report_content).decode('utf-8')
        data = json.loads(decoded)
        return data.get('results', [])
    except Exception as e:
        log_event(f'Could not parse report content: {e}', 'error')
        return []
 
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

        # Try to find the file in the local clone
        # Semgrep paths are relative to scan directory
        local_path = os.path.join(WEBGOAT_LOCAL, path_normalized)

        if os.path.exists(local_path):
            groups.setdefault(local_path, []).append(f)
        else:
            # Try stripping leading path components
            parts = path_normalized.split('/')
            for i in range(len(parts)):
                candidate = os.path.join(WEBGOAT_LOCAL, *parts[i:])
                if os.path.exists(candidate):
                    groups.setdefault(candidate, []).append(f)
                    break
            else:
                log.warning(f'File not found for fixing: {path_normalized}')
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

@app.route('/api/debug')
def api_debug():
    return jsonify({
        'GH_API_TOKEN_set': bool(os.getenv('GH_API_TOKEN', '')),
        'GH_API_TOKEN_length': len(os.getenv('GH_API_TOKEN', '')),
        'GITHUB_TOKEN_API_set': bool(GITHUB_TOKEN_API),
        'GITHUB_TOKEN_API_length': len(GITHUB_TOKEN_API),
        'all_env_keys': [k for k in os.environ.keys() if 'TOKEN' in k.upper() or 'GH' in k.upper() or 'GITHUB' in k.upper()],
    })

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
    print(f'GITHUB_TOKEN_API set: {bool(GITHUB_TOKEN_API)}')
    print(f'GITHUB_TOKEN_API length: {len(GITHUB_TOKEN_API)}')
    print(f'All env vars: {[k for k in os.environ.keys() if "GITHUB" in k or "TOKEN" in k]}')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
