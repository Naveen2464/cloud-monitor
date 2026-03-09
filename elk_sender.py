import json
import urllib.request
from datetime import datetime, timezone

ES_HOST = "http://localhost:9200"

def send_to_es(index, doc):
    try:
        doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
        data = json.dumps(doc).encode("utf-8")
        req = urllib.request.Request(
            f"{ES_HOST}/{index}/_doc",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass

def send_login_event(username, status, ip, message, attempt=None):
    doc = {
        "event_type": "login",
        "username":   username,
        "status":     status,
        "client_ip":  ip,
        "message":    message,
        "log_source": "flask_app",
    }
    if attempt:
        doc["attempt_number"] = attempt
    send_to_es("login-events", doc)
    send_to_es("cloud-monitor", doc)

def send_brute_force(username, ip, attempt_count):
    doc = {
        "event_type":    "brute_force",
        "username":      username,
        "client_ip":     ip,
        "attempt_count": attempt_count,
        "severity":      "CRITICAL",
        "message":       f"BRUTE FORCE: {username} locked after {attempt_count} attempts from {ip}",
        "log_source":    "flask_app",
        "tags":          ["brute_force", "security_alert"],
    }
    send_to_es("security-alerts", doc)
    send_to_es("cloud-monitor", doc)

def send_session_event(username, ip, event):
    doc = {
        "event_type": "session",
        "username":   username,
        "client_ip":  ip,
        "action":     event,
        "log_source": "flask_app",
    }
    send_to_es("sessions", doc)
    send_to_es("cloud-monitor", doc)

def send_alert(alert_type, severity, message, username=""):
    doc = {
        "event_type": "alert",
        "alert_type": alert_type,
        "severity":   severity,
        "message":    message,
        "username":   username,
        "log_source": "flask_app",
        "tags":       ["alert", severity.lower()],
    }
    send_to_es("security-alerts", doc)
    send_to_es("cloud-monitor", doc)

def send_user_event(action, target_username, admin_username):
    doc = {
        "event_type":      "user_management",
        "action":          action,
        "target_username": target_username,
        "admin_username":  admin_username,
        "log_source":      "flask_app",
    }
    send_to_es("cloud-monitor", doc)

def check_es_connection():
    try:
        req = urllib.request.Request(f"{ES_HOST}/_cluster/health")
        res = urllib.request.urlopen(req, timeout=3)
        data = json.loads(res.read())
        return data.get("status") in ["green", "yellow"]
    except Exception:
        return False