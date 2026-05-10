import sqlite3, json, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'poc.db')

class Database:
    def __init__(self):
        self._init_db()

    def _conn(self):
        return sqlite3.connect(DB_PATH)

    def _init_db(self):
        with self._conn() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_type TEXT, pipeline_id TEXT, findings_json TEXT, total INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    def save_scan(self, scan_type, findings, pipeline_id=''):
        with self._conn() as c:
            c.execute('INSERT INTO scans (scan_type, pipeline_id, findings_json, total) VALUES (?,?,?,?)', (scan_type, pipeline_id, json.dumps(findings[:200]), len(findings)))

    def clear(self):
        with self._conn() as c:
            c.execute('DELETE FROM scans')