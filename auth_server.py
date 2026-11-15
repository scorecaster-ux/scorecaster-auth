"""
Score Caster — Cloud Auth Server
================================
Single-file Flask app + SQLite. No UUID licensing: users register, the admin
approves them from the web panel, and the desktop app validates the login here.

Endpoints (for the desktop app):
    POST /api/register   {username, password}
    POST /api/login      {username, password}  -> {token, username, expiry}
    POST /api/verify     {token}               -> {ok, username, expiry}

Admin panel:
    GET  /admin                 (web page)
    POST /api/admin/login       {password}
    GET  /api/admin/users
    POST /api/admin/action      {action, username, ...}

Run locally:   python auth_server.py          -> http://127.0.0.1:8100
Deploy:        Render web service (this folder) + a DATABASE_URL env var
               (Neon Postgres). Falls back to local SQLite when unset.
"""
import datetime
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "users.db")
ADMIN_HINT_PATH = os.path.join(BASE, "admin_pass.txt")
ADMIN_HTML = os.path.join(BASE, "admin.html")

# When DATABASE_URL is set (e.g. Render + Neon Postgres) all state lives in that
# database and survives restarts/spin-downs. Otherwise a local SQLite file is used.
DATABASE_URL = (os.environ.get("DATABASE_URL") or "").strip()
IS_POSTGRES = bool(DATABASE_URL)

PBKDF2_ITERS = 120_000
TOKEN_TTL_SECONDS = 7 * 24 * 3600          # app session token lifetime (7 days)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,24}$")

app = Flask(__name__)

SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE COLLATE NOCASE,
    pass_hash TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'pending',   -- pending | active | suspended
    expiry    TEXT,                              -- YYYY-MM-DD or '' (no expiry)
    created   TEXT,
    last_seen TEXT,
    last_ip   TEXT,
    note      TEXT,
    session_nonce TEXT,                           -- single-session: current login's ID
    device_id   TEXT                              -- device lock: machine this account is bound to
);
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""
SCHEMA_PG = """
CREATE TABLE IF NOT EXISTS users (
    id        SERIAL PRIMARY KEY,
    username  TEXT UNIQUE,
    pass_hash TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'pending',
    expiry    TEXT,
    created   TEXT,
    last_seen TEXT,
    last_ip   TEXT,
    note      TEXT,
    session_nonce TEXT,
    device_id   TEXT
);
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


# ─── secrets ────────────────────────────────────────────────────────────────
SECRET = None   # loaded from the database by init_db()


class _Db:
    """Thin wrapper so the same SQL calls work on SQLite and Postgres."""

    def __init__(self):
        if IS_POSTGRES:
            import psycopg2
            import psycopg2.extras
            url = DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            self.conn = psycopg2.connect(url, sslmode="require")
            self.conn.autocommit = True
        else:
            self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA busy_timeout=5000")

    def _fix(self, sql):
        # Postgres uses %s placeholders; SQLite uses ?
        return sql.replace("?", "%s") if IS_POSTGRES else sql

    def query(self, sql, args=()):
        cur = self.conn.cursor()
        cur.execute(self._fix(sql), args)
        return cur

    def rows(self, sql, args=()):
        sql = self._fix(sql)
        if IS_POSTGRES:
            import psycopg2.extras
            cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(sql, args)
            return [dict(r) for r in cur.fetchall()]
        cur = self.conn.cursor()
        cur.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]

    def one(self, sql, args=()):
        rs = self.rows(sql, args)
        return rs[0] if rs else None

    def execute(self, sql, args=()):
        self.query(sql, args)
        if not IS_POSTGRES:
            self.conn.commit()

    def commit(self):
        if not IS_POSTGRES:
            self.conn.commit()


def init_db():
    con = _Db()
    if IS_POSTGRES:
        cur = con.query(SCHEMA_PG)
        cur.close()
    else:
        con.conn.executescript(SCHEMA_SQLITE)
        con.commit()
    # Migration for DBs created before single-session enforcement:
    # add the session_nonce column if it is missing.
    if IS_POSTGRES:
        for col in ("session_nonce", "device_id"):
            exists = con.one(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name='users' AND column_name=%s", (col,))
            if not exists:
                con.query(f"ALTER TABLE users ADD COLUMN {col} TEXT").close()
    else:
        cols = [r["name"] for r in con.rows("PRAGMA table_info(users)")]
        for col in ("session_nonce", "device_id"):
            if col not in cols:
                con.query(f"ALTER TABLE users ADD COLUMN {col} TEXT")
    # Persistent server secret lives in the DB so tokens survive restarts.
    if not con.one("SELECT value FROM config WHERE key='server_secret'"):
        con.execute("INSERT INTO config(key, value) VALUES('server_secret', ?)",
                    (secrets.token_hex(32),))
        con.commit()
    global SECRET
    SECRET = con.one("SELECT value FROM config WHERE key='server_secret'")["value"]
    app.secret_key = hmac.new(SECRET.encode(), b"admin-cookie", hashlib.sha256).hexdigest()
    # First run: create the admin password
    if not con.one("SELECT 1 FROM config WHERE key='admin_pass_hash'"):
        env_pw = (os.environ.get("ADMIN_PASSWORD") or "").strip()
        pw = env_pw if env_pw else secrets.token_urlsafe(9)
        con.execute("INSERT INTO config(key, value) VALUES('admin_pass_hash', ?)",
                    (hash_password(pw),))
        con.commit()
        if env_pw:
            print("*" * 60)
            print("  Admin panel password taken from the ADMIN_PASSWORD env var.")
            print("*" * 60)
        else:
            try:
                with open(ADMIN_HINT_PATH, "w") as fh:
                    fh.write(pw + "\n")
                print("*" * 60)
                print(f"  FIRST RUN — admin panel password: {pw}")
                print(f"  (also saved in {ADMIN_HINT_PATH} — delete it after noting it)")
                print("*" * 60)
            except OSError:
                print(f"  FIRST RUN — admin panel password: {pw}")
                print("  (write it down — it is not stored in plain text anywhere)")


# ─── passwords / tokens ─────────────────────────────────────────────────────
def db():
    """Request-scoped connection (SQLite locally, Postgres when DATABASE_URL set)."""
    if "db" not in g:
        g.db = _Db()
    return g.db


@app.teardown_appcontext
def _close_db(exc):
    d = g.pop("db", None)
    if d is not None:
        try:
            d.conn.close()
        except Exception:
            pass


def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERS)
    return f"pbkdf2${PBKDF2_ITERS}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        _name, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def make_token(username, nonce):
    payload = f"{username}|{int(time.time()) + TOKEN_TTL_SECONDS}|{nonce}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    raw = f"{payload}|{sig}"
    # token itself is not secret (it travels over TLS), base64 keeps it one blob
    import base64
    return base64.urlsafe_b64encode(raw.encode()).decode()


def read_token(token):
    """Returns (username, nonce) for a valid token, else None."""
    import base64
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, exp, nonce, sig = raw.split("|", 3)
        payload = f"{username}|{exp}|{nonce}"
        good = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, good):
            return None
        if int(exp) < time.time():
            return None
        return username, nonce
    except Exception:
        return None


def client_ip():
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr or "?")


def today():
    return datetime.date.today().isoformat()


def account_expired(row):
    return bool(row["expiry"]) and row["expiry"] < today()


# ─── app endpoints ──────────────────────────────────────────────────────────
@app.get("/")
def index():
    return jsonify(ok=True, service="Score Caster Auth", version="1.0")


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    if not USERNAME_RE.match(username):
        return jsonify(ok=False, error="Username must be 3-24 letters/numbers/dots/underscores"), 400
    if len(password) < 4:
        return jsonify(ok=False, error="Password must be at least 4 characters"), 400
    con = db()
    if con.one("SELECT 1 FROM users WHERE username=?", (username,)):
        return jsonify(ok=False, error="Username already taken"), 409
    con.execute(
        "INSERT INTO users(username, pass_hash, status, expiry, created) VALUES(?,?,?,?,?)",
        (username, hash_password(password), "pending", "", today()))
    con.commit()
    return jsonify(ok=True, message="Account created. Waiting for admin approval.")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    con = db()
    row = con.one("SELECT * FROM users WHERE username=?", (username,))
    if not row or not verify_password(password, row["pass_hash"]):
        return jsonify(ok=False, error="Wrong username or password"), 401
    if row["status"] == "pending":
        return jsonify(ok=False, error="Account still waiting for admin approval"), 403
    if row["status"] == "suspended":
        return jsonify(ok=False, error="Account suspended. Contact Score Caster support."), 403
    if account_expired(row):
        return jsonify(ok=False, error=f"Account expired on {row['expiry']}. Renew to continue."), 403
    # Device lock: the account is bound to the first PC it logs in from.
    # Other PCs are rejected until the admin resets the device binding.
    device_id = str(data.get("device_id", "")).strip()
    if device_id:
        if (row["device_id"] or "") and row["device_id"] != device_id:
            return jsonify(ok=False,
                           error="This account is locked to another device. "
                                 "Contact Score Caster support to move it."), 403
        if not (row["device_id"] or ""):
            con.execute("UPDATE users SET device_id=? WHERE id=?", (device_id, row["id"]))
            con.commit()
    # Single-session: every login mints a new session ID. Any older session
    # (another PC) loses its match on the next /api/verify and is kicked out.
    nonce = secrets.token_urlsafe(16)
    con.execute("UPDATE users SET last_seen=?, last_ip=?, session_nonce=? WHERE id=?",
                (datetime.datetime.now().isoformat(timespec="seconds"), client_ip(),
                 nonce, row["id"]))
    con.commit()
    return jsonify(ok=True, token=make_token(row["username"], nonce),
                   username=row["username"], expiry=row["expiry"] or "")


@app.post("/api/verify")
def verify():
    """The app calls this periodically; the DB remains the source of truth."""
    data = request.get_json(silent=True) or {}
    tok = read_token(str(data.get("token", "")))
    if not tok:
        return jsonify(ok=False, error="Session expired. Sign in again."), 401
    username, nonce = tok
    con = db()
    row = con.one("SELECT * FROM users WHERE username=?", (username,))
    if not row:
        return jsonify(ok=False, error="Account no longer exists"), 403
    if row["status"] != "active":
        return jsonify(ok=False, error=f"Account {row['status']}"), 403
    if account_expired(row):
        return jsonify(ok=False, error=f"Account expired on {row['expiry']}"), 403
    # Single-session check: a newer login (other device) replaced the nonce.
    if (row["session_nonce"] or "") != nonce:
        return jsonify(ok=False,
                       error="Signed in on another device. This session was logged out."), 403
    # Device lock check (only enforced when the client reports its device).
    device_id = str(data.get("device_id", "")).strip()
    if device_id and (row["device_id"] or "") and row["device_id"] != device_id:
        return jsonify(ok=False,
                       error="This account is locked to another device. "
                             "Contact Score Caster support to move it."), 403
    con.execute("UPDATE users SET last_seen=?, last_ip=? WHERE id=?",
                (datetime.datetime.now().isoformat(timespec="seconds"), client_ip(), row["id"]))
    con.commit()
    return jsonify(ok=True, username=row["username"], expiry=row["expiry"] or "")


# ─── admin ──────────────────────────────────────────────────────────────────
def web_session_flag():
    from flask import session as s
    return bool(s.get("admin"))


@app.get("/admin")
def admin_page():
    return send_from_directory(BASE, "admin.html")


@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    pw = str(data.get("password", ""))
    con = db()
    row = con.one("SELECT value FROM config WHERE key='admin_pass_hash'")
    if row and verify_password(pw, row["value"]):
        from flask import session as s
        s["admin"] = True
        s.permanent = True
        return jsonify(ok=True)
    return jsonify(ok=False, error="Wrong admin password"), 401


@app.post("/api/admin/logout")
def admin_logout():
    from flask import session as s
    s.clear()
    return jsonify(ok=True)


@app.get("/api/admin/users")
def admin_users():
    if not web_session_flag():
        return jsonify(ok=False, error="Admin login required"), 401
    rows = db().rows(
        "SELECT username, status, expiry, created, last_seen, last_ip, note, device_id "
        "FROM users ORDER BY id DESC")
    return jsonify(ok=True, users=rows)


@app.post("/api/admin/action")
def admin_action():
    if not web_session_flag():
        return jsonify(ok=False, error="Admin login required"), 401
    data = request.get_json(silent=True) or {}
    action = str(data.get("action", ""))
    username = str(data.get("username", "")).strip().lower()
    con = db()
    row = con.one("SELECT * FROM users WHERE username=?", (username,))

    if action == "create":
        new_user = str(data.get("new_username", "")).strip().lower()
        pw = str(data.get("password", ""))
        expiry = str(data.get("expiry", "")).strip()
        if not USERNAME_RE.match(new_user):
            return jsonify(ok=False, error="Invalid username"), 400
        if len(pw) < 4:
            return jsonify(ok=False, error="Password too short"), 400
        if con.one("SELECT 1 FROM users WHERE username=?", (new_user,)):
            return jsonify(ok=False, error="Username already taken"), 409
        con.execute(
            "INSERT INTO users(username, pass_hash, status, expiry, created) VALUES(?,?,?,?,?)",
            (new_user, hash_password(pw), "active", expiry, today()))
        con.commit()
        return jsonify(ok=True, message=f"Created {new_user}")

    if not row:
        return jsonify(ok=False, error="User not found"), 404

    if action == "approve":
        months = int(data.get("months", 1) or 1)
        expiry = (datetime.date.today() +
                  datetime.timedelta(days=30 * months)).isoformat()
        con.execute("UPDATE users SET status='active', expiry=? WHERE username=?",
                    (expiry, username))
        con.commit()
        return jsonify(ok=True, message=f"{username} approved until {expiry}")
    if action == "suspend":
        con.execute("UPDATE users SET status='suspended' WHERE username=?", (username,))
        con.commit()
        return jsonify(ok=True, message=f"{username} suspended")
    if action == "activate":
        con.execute("UPDATE users SET status='active' WHERE username=?", (username,))
        con.commit()
        return jsonify(ok=True, message=f"{username} activated")
    if action == "delete":
        con.execute("DELETE FROM users WHERE username=?", (username,))
        con.commit()
        return jsonify(ok=True, message=f"{username} deleted")
    if action == "set_expiry":
        expiry = str(data.get("expiry", "")).strip()
        if expiry:
            try:
                datetime.date.fromisoformat(expiry)
            except ValueError:
                return jsonify(ok=False, error="Expiry must be YYYY-MM-DD"), 400
        con.execute("UPDATE users SET expiry=? WHERE username=?", (expiry, username))
        con.commit()
        return jsonify(ok=True, message=f"{username} expiry set to {expiry or 'never'}")
    if action == "set_password":
        pw = str(data.get("password", ""))
        if len(pw) < 4:
            return jsonify(ok=False, error="Password too short"), 400
        con.execute("UPDATE users SET pass_hash=? WHERE username=?",
                    (hash_password(pw), username))
        con.commit()
        return jsonify(ok=True, message=f"{username} password reset")
    if action == "reset_device":
        con.execute("UPDATE users SET device_id='' WHERE username=?", (username,))
        con.commit()
        return jsonify(ok=True, message=f"{username} device lock cleared - "
                                        f"next login re-binds the account")
    return jsonify(ok=False, error="Unknown action"), 400


# init runs on import too, so gunicorn works and the DB/secret/admin password
# are always ready before the first request (idempotent — safe to run again).
# NOTE: must run BEFORE __main__ below — app.run() blocks.
try:
    init_db()
except Exception as _init_exc:      # transient DB errors shouldn't kill the worker
    import logging
    logging.getLogger("auth").error(f"init_db failed: {_init_exc}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8100))
    app.run(host="0.0.0.0", port=port, debug=False)
