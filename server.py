#!/usr/bin/env python3
"""Minimal same-origin registration service for the campus hackathon."""
import csv
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from management import Management

os.umask(0o077)
DATABASE = Path(os.environ.get('KIRO_DATABASE', '/var/lib/kiro-hackathon/registrations.sqlite3'))
REGISTRATION_OPEN = os.environ.get('KIRO_REGISTRATION_OPEN', '0') == '1'
PREVIEW = os.environ.get('KIRO_PREVIEW', '0') == '1'
DIST = Path(__file__).resolve().parent.parent / 'dist'
PORT = int(os.environ.get('KIRO_PORT', '8826'))
ALLOWED_ORIGINS = set(filter(None, os.environ.get('KIRO_ALLOWED_ORIGINS', '').split(',')))
MAX_BYTES = 8192
LIMIT_WINDOW = 60
LIMIT_COUNT = 60
RATE_LOCK = threading.Lock()
RATE = defaultdict(deque)
MANAGEMENT = None


def connect():
    DATABASE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(str(DATABASE), timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS registrations (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, name TEXT NOT NULL, affiliation TEXT NOT NULL, contact TEXT NOT NULL, message TEXT NOT NULL)')
    columns = {row[1] for row in db.execute('PRAGMA table_info(registrations)')}
    for name in ('track', 'team_status', 'team_name', 'role'):
        if name not in columns:
            db.execute('ALTER TABLE registrations ADD COLUMN ' + name + " TEXT NOT NULL DEFAULT ''")
    if MANAGEMENT is not None:
        MANAGEMENT.init(db)
    db.commit()
    DATABASE.chmod(0o600)
    return db


def field(data, key, maximum, required=True, multiline=False):
    value = data.get(key, '')
    if not isinstance(value, str):
        raise ValueError('invalid field')
    value = value.strip()
    if (required and not value) or len(value) > maximum:
        raise ValueError('invalid field')
    if any(ord(c) < 32 and not (multiline and c in '\n\r\t') for c in value):
        raise ValueError('invalid field')
    return value


def is_rate_limited(client):
    now = time.monotonic()
    with RATE_LOCK:
        entries = RATE[client]
        while entries and entries[0] < now - LIMIT_WINDOW:
            entries.popleft()
        if len(entries) >= LIMIT_COUNT:
            return True
        entries.append(now)
        if len(RATE) > 5000:
            for key in list(RATE):
                if not RATE[key] or RATE[key][-1] < now - LIMIT_WINDOW:
                    del RATE[key]
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = 'HackathonRegistration'
    sys_version = ''

    def log_message(self, _format, *args):
        # Names, contact details, and request bodies are never written to logs.
        return

    def send_bytes(self, code, raw, content_type, headers=None):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def respond(self, code, data, headers=None):
        raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_bytes(code, raw, 'application/json; charset=utf-8', headers)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/api/status':
            self.respond(200, {'registration_open': REGISTRATION_OPEN})
            return
        try:
            if MANAGEMENT and MANAGEMENT.get(self, path):
                return
        except (sqlite3.Error, OSError, ValueError):
            self.respond(503, {'ok': False})
            return
        if PREVIEW and path in ('/', '/index.html', '/register.html', '/styles.css', '/app.js', '/assets/campus-pixel-robot.png', '/assets/kiro-icon.svg', '/assets/kiro-ghost.svg', '/admin/', '/admin/index.html', '/admin/admin.css', '/admin/admin.js'):
            target = DIST / ('index.html' if path == '/' else 'admin/index.html' if path == '/admin/' else path[1:])
            raw = target.read_bytes()
            mime = {'html':'text/html', 'css':'text/css', 'js':'application/javascript', 'png':'image/png', 'svg':'image/svg+xml'}[target.suffix[1:]]
            self.send_response(200)
            self.send_header('Content-Type', mime + '; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.respond(404, {'ok': False})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path.startswith('/api/admin/'):
            try:
                MANAGEMENT.post(self, path)
            except (sqlite3.Error, OSError):
                self.respond(503, {'ok': False, 'error': '服务暂不可用'})
            return
        if path != '/api/registrations':
            self.respond(404, {'ok': False})
            return
        if not REGISTRATION_OPEN:
            self.respond(503, {'ok': False})
            return
        origin = self.headers.get('Origin')
        if origin and origin not in ALLOWED_ORIGINS:
            self.respond(403, {'ok': False})
            return
        client = self.headers.get('X-Real-IP', self.client_address[0])[:100]
        if is_rate_limited(client):
            self.respond(429, {'ok': False})
            return
        try:
            if self.headers.get_content_type() != 'application/json':
                raise ValueError('invalid content type')
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > MAX_BYTES:
                raise ValueError('invalid length')
            data = json.loads(self.rfile.read(length).decode('utf-8'))
            if not isinstance(data, dict) or data.get('consent') is not True:
                raise ValueError('missing consent')
            if field(data, 'website', 200, required=False):
                self.respond(200, {'ok': True})
                return
            name = field(data, 'name', 40)
            affiliation = field(data, 'affiliation', 100)
            contact = field(data, 'contact', 120)
            message = field(data, 'message', 500, required=False, multiline=True)
            track = field(data, 'track', 40, required=False)
            team_status = field(data, 'team_status', 40, required=False)
            team_name = field(data, 'team_name', 80, required=False)
            role = field(data, 'role', 40, required=False)
            if track and track not in ('校园奇妙物', '校园开挂术', '一点小温暖'):
                raise ValueError('invalid track')
            if team_status and team_status not in ('个人报名', '已有队伍'):
                raise ValueError('invalid team status')
            if role and role not in ('开发', '设计', '产品策划', '创意与其他'):
                raise ValueError('invalid role')
            with closing(connect()) as db:
                with db:
                    db.execute('INSERT INTO registrations (created_at, name, affiliation, contact, message, track, team_status, team_name, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (datetime.now(timezone.utc).isoformat(), name, affiliation, contact, message, track, team_status, team_name, role))
            self.respond(201, {'ok': True})
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.respond(400, {'ok': False})
        except sqlite3.Error:
            self.respond(503, {'ok': False})


def csv_safe(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else text


def export():
    if not DATABASE.is_file():
        raise SystemExit('Registration database does not exist')
    with closing(sqlite3.connect(DATABASE.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        rows = db.execute('SELECT created_at, name, affiliation, contact, track, team_status, team_name, role, message FROM registrations ORDER BY id').fetchall()
    writer = csv.writer(sys.stdout)
    writer.writerow(['提交时间（UTC）', '姓名', '学校或院系', '联系方式', '赛道', '参与方式', '队伍名称', '擅长方向', '想法'])
    writer.writerows([[csv_safe(value) for value in row] for row in rows])


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'export':
        export()
    else:
        MANAGEMENT = Management(connect, DATABASE.parent, ALLOWED_ORIGINS, PREVIEW)
        with closing(connect()):
            pass
        server = ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
        server.daemon_threads = True
        print('Hackathon registration service listening on localhost', flush=True)
        server.serve_forever()
