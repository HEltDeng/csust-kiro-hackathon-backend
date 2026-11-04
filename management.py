#!/usr/bin/env python3
"""Authenticated event management, announcements, and SMTP forwarding."""
import csv
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone
from email.message import EmailMessage
from http.cookies import SimpleCookie
from urllib.parse import urlsplit


ITERATIONS = 600_000
SESSION_TTL = 8 * 60 * 60
EMAIL = re.compile(r'^[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}$')
HOST = re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$')


def now():
    return datetime.now(timezone.utc).isoformat()


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    value = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), ITERATIONS).hex()
    return salt, value


def text(value, maximum, required=True, multiline=False):
    if not isinstance(value, str):
        raise ValueError('invalid field')
    value = value.strip()
    if (required and not value) or len(value) > maximum:
        raise ValueError('invalid field')
    if any(ord(c) < 32 and not (multiline and c in '\n\r\t') for c in value):
        raise ValueError('invalid field')
    return value


def valid_email(value):
    value = text(value, 254)
    if not EMAIL.fullmatch(value):
        raise ValueError('invalid email')
    return value


def init_tables(db, state_dir):
    db.execute('CREATE TABLE IF NOT EXISTS admin_account (id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS announcements (id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, published_at TEXT)')
    bootstrap = state_dir / 'admin-bootstrap.json'
    if not db.execute('SELECT 1 FROM admin_account WHERE id = 1').fetchone() and bootstrap.is_file():
        payload = json.loads(bootstrap.read_text(encoding='utf-8'))
        username = text(payload['username'], 80)
        salt = payload['salt']
        hashed = payload['password_hash']
        if not re.fullmatch(r'[0-9a-f]{32}', salt) or not re.fullmatch(r'[0-9a-f]{64}', hashed):
            raise ValueError('invalid bootstrap credentials')
        db.execute('INSERT INTO admin_account VALUES (1, ?, ?, ?)', (username, salt, hashed))
        db.commit()
        bootstrap.unlink()


class Management:
    def __init__(self, connect, state_dir, allowed_origins, preview=False):
        self.connect = connect
        self.state_dir = state_dir
        self.allowed_origins = allowed_origins
        self.preview = preview
        self.sessions = {}
        self.attempts = defaultdict(deque)
        self.lock = threading.Lock()

    def init(self, db):
        init_tables(db, self.state_dir)

    def client(self, h):
        return h.headers.get('X-Real-IP', h.client_address[0])[:100]

    def valid_origin(self, h):
        return h.headers.get('Origin') in self.allowed_origins

    def limited_login(self, client):
        now_mono = time.monotonic()
        with self.lock:
            entries = self.attempts[client]
            while entries and entries[0] < now_mono - 900:
                entries.popleft()
            if len(entries) >= 8:
                return True
            entries.append(now_mono)
            if len(self.attempts) > 5000:
                for key in list(self.attempts):
                    if not self.attempts[key] or self.attempts[key][-1] < now_mono - 900:
                        del self.attempts[key]
            return False

    def session(self, h):
        try:
            cookie = SimpleCookie()
            cookie.load(h.headers.get('Cookie', ''))
            token = cookie['kiro_admin'].value
        except (KeyError, ValueError):
            return None
        key = hashlib.sha256(token.encode('utf-8')).hexdigest()
        with self.lock:
            session = self.sessions.get(key)
            if not session or session['expires'] < time.monotonic():
                self.sessions.pop(key, None)
                return None
            return key, session

    def cookie(self, token, age=SESSION_TTL):
        path = '/' if self.preview else '/events/kiro-2026/'
        secure = '' if self.preview else '; Secure'
        return 'kiro_admin=' + token + '; Path=' + path + '; Max-Age=' + str(age) + '; HttpOnly; SameSite=Strict' + secure

    def require(self, h, write=False):
        session = self.session(h)
        if not session:
            h.respond(401, {'ok': False, 'error': '请先登录'})
            return None
        if write and (not self.valid_origin(h) or not hmac.compare_digest(h.headers.get('X-CSRF-Token', ''), session[1]['csrf'])):
            h.respond(403, {'ok': False, 'error': '请求验证失败，请刷新页面重试'})
            return None
        return session

    def read_json(self, h):
        if h.headers.get_content_type() != 'application/json':
            raise ValueError('invalid content type')
        length = int(h.headers.get('Content-Length', '0'))
        if length <= 0 or length > 32768:
            raise ValueError('invalid length')
        obj = json.loads(h.rfile.read(length).decode('utf-8'))
        if not isinstance(obj, dict):
            raise ValueError('invalid payload')
        return obj

    def get(self, h, path):
        if path == '/api/announcements':
            with closing(self.connect()) as db:
                rows = db.execute('SELECT id, title, body, published_at FROM announcements WHERE published = 1 ORDER BY published_at DESC, id DESC LIMIT 30').fetchall()
            h.respond(200, {'announcements': [dict(zip(('id', 'title', 'body', 'published_at'), row)) for row in rows]})
            return True
        if not path.startswith('/api/admin/'):
            return False
        session = self.require(h)
        if not session:
            return True
        if path == '/api/admin/session':
            h.respond(200, {'ok': True, 'csrf': session[1]['csrf']})
        elif path == '/api/admin/registrations':
            with closing(self.connect()) as db:
                rows = db.execute('SELECT id, created_at, name, affiliation, contact, track, team_status, team_name, role, message FROM registrations ORDER BY id DESC LIMIT 2000').fetchall()
            keys = ('id', 'created_at', 'name', 'affiliation', 'contact', 'track', 'team_status', 'team_name', 'role', 'message')
            h.respond(200, {'ok': True, 'registrations': [dict(zip(keys, row)) for row in rows]})
        elif path == '/api/admin/registrations.csv':
            with closing(self.connect()) as db:
                rows = db.execute('SELECT created_at, name, affiliation, contact, track, team_status, team_name, role, message FROM registrations ORDER BY id').fetchall()
            output = io.StringIO(newline='')
            writer = csv.writer(output)
            writer.writerow(['提交时间（UTC）', '姓名', '学校或院系', '联系方式', '赛道', '参与方式', '队伍名称', '擅长方向', '想法'])
            for row in rows:
                writer.writerow([("'" + str(v) if str(v).lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else str(v)) for v in row])
            h.send_bytes(200, output.getvalue().encode('utf-8-sig'), 'text/csv; charset=utf-8', {'Content-Disposition': 'attachment; filename="registrations.csv"'})
        elif path == '/api/admin/announcements':
            with closing(self.connect()) as db:
                rows = db.execute('SELECT id, title, body, published, updated_at, published_at FROM announcements ORDER BY updated_at DESC, id DESC LIMIT 200').fetchall()
            keys = ('id', 'title', 'body', 'published', 'updated_at', 'published_at')
            h.respond(200, {'ok': True, 'announcements': [dict(zip(keys, row)) for row in rows]})
        elif path == '/api/admin/mail-settings':
            config = self.mail_config()
            h.respond(200, {'ok': True, 'mail': {key: config.get(key, '') for key in ('host', 'port', 'security', 'username', 'from_address', 'from_name')}, 'password_configured': bool(config.get('password'))})
        else:
            h.respond(404, {'ok': False})
        return True

    def post(self, h, path):
        if not path.startswith('/api/admin/'):
            return False
        if not self.valid_origin(h):
            h.respond(403, {'ok': False, 'error': '请求来源不受信任'})
            return True
        try:
            if path == '/api/admin/login':
                self.login(h)
                return True
            session = self.require(h, write=True)
            if not session:
                return True
            if path == '/api/admin/logout':
                with self.lock:
                    self.sessions.pop(session[0], None)
                h.respond(200, {'ok': True}, {'Set-Cookie': self.cookie('', 0)})
            elif path == '/api/admin/announcement':
                self.save_announcement(h)
            elif path == '/api/admin/mail-settings':
                self.save_mail_settings(h)
            elif path == '/api/admin/forward':
                self.forward(h)
            elif path == '/api/admin/password':
                self.change_password(h)
            else:
                h.respond(404, {'ok': False})
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
            h.respond(400, {'ok': False, 'error': '请检查填写内容'})
        except (OSError, smtplib.SMTPException):
            h.respond(503, {'ok': False, 'error': '邮件或服务暂不可用，请检查配置后重试'})
        return True

    def login(self, h):
        if self.limited_login(self.client(h)):
            h.respond(429, {'ok': False, 'error': '尝试次数过多，请稍后再试'})
            return
        data = self.read_json(h)
        username = text(data.get('username', ''), 80)
        password = text(data.get('password', ''), 256)
        with closing(self.connect()) as db:
            account = db.execute('SELECT username, salt, password_hash FROM admin_account WHERE id = 1').fetchone()
        if not account:
            h.respond(503, {'ok': False, 'error': '管理员账号尚未配置'})
            return
        candidate = password_hash(password, account[1])[1]
        if not hmac.compare_digest(username, account[0]) or not hmac.compare_digest(candidate, account[2]):
            h.respond(401, {'ok': False, 'error': '账号或密码不正确'})
            return
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v['expires'] >= time.monotonic()}
            self.sessions[key] = {'csrf': csrf, 'expires': time.monotonic() + SESSION_TTL}
            self.attempts.pop(self.client(h), None)
        h.respond(200, {'ok': True, 'csrf': csrf}, {'Set-Cookie': self.cookie(token)})

    def save_announcement(self, h):
        data = self.read_json(h)
        title = text(data.get('title', ''), 100)
        body = text(data.get('body', ''), 4000, multiline=True)
        published = data.get('published')
        if not isinstance(published, bool):
            raise ValueError('invalid status')
        record_id = data.get('id')
        if record_id is not None and (type(record_id) is not int or record_id < 1):
            raise ValueError('invalid id')
        timestamp = now()
        with closing(self.connect()) as db:
            with db:
                if record_id is None:
                    cursor = db.execute('INSERT INTO announcements (title, body, published, created_at, updated_at, published_at) VALUES (?, ?, ?, ?, ?, ?)', (title, body, int(published), timestamp, timestamp, timestamp if published else None))
                    record_id = cursor.lastrowid
                else:
                    previous = db.execute('SELECT published, published_at FROM announcements WHERE id = ?', (record_id,)).fetchone()
                    if not previous:
                        h.respond(404, {'ok': False, 'error': '内容不存在'})
                        return
                    published_at = (previous[1] if previous[0] else timestamp) if published else None
                    db.execute('UPDATE announcements SET title = ?, body = ?, published = ?, updated_at = ?, published_at = ? WHERE id = ?', (title, body, int(published), timestamp, published_at, record_id))
        h.respond(200, {'ok': True, 'id': record_id})

    def mail_config(self):
        path = self.state_dir / 'mail-settings.json'
        if not path.is_file():
            return {}
        return json.loads(path.read_text(encoding='utf-8'))

    def save_mail_settings(self, h):
        data = self.read_json(h)
        old = self.mail_config()
        host = text(data.get('host', ''), 253).lower()
        if not HOST.fullmatch(host):
            raise ValueError('invalid host')
        port = int(data.get('port', 0))
        security = text(data.get('security', ''), 12)
        if (security, port) not in (('ssl', 465), ('starttls', 587)):
            raise ValueError('encrypted SMTP is required')
        config = {'host': host, 'port': port, 'security': security, 'username': text(data.get('username', ''), 254), 'from_address': valid_email(data.get('from_address', '')), 'from_name': text(data.get('from_name', ''), 80, required=False), 'password': text(data.get('password', ''), 256, required=False) or old.get('password', '')}
        if not config['password']:
            raise ValueError('missing authorization code')
        path = self.state_dir / 'mail-settings.json'
        tmp = self.state_dir / ('.mail-settings-' + secrets.token_hex(8))
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                json.dump(config, out, ensure_ascii=False)
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()
        h.respond(200, {'ok': True})

    def forward(self, h):
        data = self.read_json(h)
        recipient = valid_email(data.get('recipient', ''))
        record_id = data.get('id')
        if type(record_id) is not int or record_id < 1:
            raise ValueError('invalid id')
        config = self.mail_config()
        if not config.get('password'):
            h.respond(409, {'ok': False, 'error': '请先完成企业邮箱配置'})
            return
        with closing(self.connect()) as db:
            row = db.execute('SELECT created_at, name, affiliation, contact, track, team_status, team_name, role, message FROM registrations WHERE id = ?', (record_id,)).fetchone()
        if not row:
            h.respond(404, {'ok': False, 'error': '报名记录不存在'})
            return
        labels = ['提交时间（UTC）', '姓名', '学校或院系', '联系方式', '赛道', '参与方式', '队伍名称', '擅长方向', '想法']
        message = EmailMessage()
        message['From'] = (config['from_name'] + ' <' + config['from_address'] + '>') if config['from_name'] else config['from_address']
        message['To'] = recipient
        message['Subject'] = 'K 校园计划 · 报名信息 #' + str(record_id)
        message.set_content('\n'.join(label + '：' + str(value) for label, value in zip(labels, row)))
        context = ssl.create_default_context()
        if config['security'] == 'ssl':
            client = smtplib.SMTP_SSL(config['host'], config['port'], timeout=15, context=context)
        else:
            client = smtplib.SMTP(config['host'], config['port'], timeout=15)
        with client:
            if config['security'] == 'starttls':
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
            client.login(config['username'], config['password'])
            client.send_message(message)
        h.respond(200, {'ok': True})

    def change_password(self, h):
        data = self.read_json(h)
        current = text(data.get('current', ''), 256)
        new = text(data.get('new', ''), 256)
        if len(new) < 14:
            raise ValueError('password too short')
        with closing(self.connect()) as db:
            account = db.execute('SELECT salt, password_hash FROM admin_account WHERE id = 1').fetchone()
            if not account or not hmac.compare_digest(password_hash(current, account[0])[1], account[1]):
                h.respond(403, {'ok': False, 'error': '当前密码不正确'})
                return
            salt, hashed = password_hash(new)
            with db:
                db.execute('UPDATE admin_account SET salt = ?, password_hash = ? WHERE id = 1', (salt, hashed))
        with self.lock:
            self.sessions.clear()
        h.respond(200, {'ok': True}, {'Set-Cookie': self.cookie('', 0)})
