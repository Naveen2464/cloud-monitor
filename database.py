import sqlite3
import hashlib
from datetime import datetime

DB_FILE = "users.db"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT UNIQUE NOT NULL,
        password    TEXT NOT NULL,
        email       TEXT,
        role        TEXT DEFAULT "user",
        created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
        is_active   INTEGER DEFAULT 1,
        is_locked   INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_logs (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        status      TEXT NOT NULL,
        ip_address  TEXT,
        timestamp   TEXT DEFAULT CURRENT_TIMESTAMP,
        message     TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL,
        login_time  TEXT,
        logout_time TEXT,
        ip_address  TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type  TEXT NOT NULL,
        severity    TEXT NOT NULL,
        message     TEXT NOT NULL,
        username    TEXT,
        timestamp   TEXT DEFAULT CURRENT_TIMESTAMP,
        resolved    INTEGER DEFAULT 0
    )''')
    conn.commit()
    default_users = [
        ("alice",   "password123", "alice@company.com",   "user"),
        ("bob",     "securepass",  "bob@company.com",     "user"),
        ("charlie", "mypassword",  "charlie@company.com", "user"),
        ("admin",   "admin123",    "admin@company.com",   "admin"),
    ]
    for username, password, email, role in default_users:
        c.execute(
            "INSERT OR IGNORE INTO users (username, password, email, role) VALUES (?,?,?,?)",
            (username, hash_password(password), email, role)
        )
    conn.commit()
    conn.close()
    print("[DB] Database initialized.")

def verify_user(username, password):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT * FROM users WHERE username=? AND password=? AND is_active=1 AND is_locked=0",
        (username, hash_password(password))
    )
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

def lock_user(username):
    conn = get_connection()
    conn.execute("UPDATE users SET is_locked=1 WHERE username=?", (username,))
    conn.commit()
    conn.close()

def unlock_user(username):
    conn = get_connection()
    conn.execute("UPDATE users SET is_locked=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()

def log_login(username, status, ip, message):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_logs (username, status, ip_address, message) VALUES (?,?,?,?)",
        (username, status, ip, message)
    )
    conn.commit()
    conn.close()

def log_session(username, ip, logout_time=None):
    conn = get_connection()
    if logout_time:
        conn.execute(
            "UPDATE sessions SET logout_time=? WHERE username=? AND logout_time IS NULL",
            (logout_time, username)
        )
    else:
        conn.execute(
            "INSERT INTO sessions (username, login_time, ip_address) VALUES (?,?,?)",
            (username, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip)
        )
    conn.commit()
    conn.close()

def save_alert(alert_type, severity, message, username=""):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO alerts (alert_type, severity, message, username) VALUES (?,?,?,?)",
        (alert_type, severity, message, username)
    )
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, created_at, is_active, is_locked FROM users")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_login_logs(limit=100):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_alerts(limit=50):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_sessions():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM sessions ORDER BY login_time DESC LIMIT 50")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_stats():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM login_logs WHERE status='SUCCESS'")
    total_success = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM login_logs WHERE status='FAILED'")
    total_failed = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'")
    total_critical = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE is_active=1")
    total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE is_locked=1")
    locked_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM sessions WHERE logout_time IS NULL")
    active_sessions = c.fetchone()[0]
    c.execute("""SELECT username, COUNT(*) as cnt FROM login_logs
                 WHERE status='FAILED' GROUP BY username ORDER BY cnt DESC LIMIT 5""")
    top_failed = [dict(r) for r in c.fetchall()]
    c.execute("""SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as cnt
                 FROM login_logs GROUP BY hour ORDER BY hour""")
    hourly = [dict(r) for r in c.fetchall()]
    conn.close()
    return {
        "total_success":   total_success,
        "total_failed":    total_failed,
        "total_critical":  total_critical,
        "total_users":     total_users,
        "locked_users":    locked_users,
        "active_sessions": active_sessions,
        "top_failed":      top_failed,
        "hourly_activity": hourly,
    }

def add_user(username, password, email, role="user"):
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)",
            (username, hash_password(password), email, role)
        )
        conn.commit()
        return True, "User created successfully"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    finally:
        conn.close()

def delete_user(user_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()