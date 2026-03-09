from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import logging
import os
from collections import defaultdict
from datetime import datetime
from database import (init_db, verify_user, log_login, log_session,
                      save_alert, lock_user, unlock_user,
                      get_all_users, get_login_logs, get_alerts,
                      get_sessions, get_stats, add_user, delete_user)
from elk_sender import (send_login_event, send_brute_force, send_session_event,
                        send_alert as elk_alert, send_user_event, check_es_connection)

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = "cloud_monitor_secret_2026"

logging.basicConfig(filename="app.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logging.getLogger("").addHandler(console)

failure_counts  = defaultdict(int)
BRUTE_THRESHOLD = 3

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        ip       = request.remote_addr
        user     = verify_user(username, password)
        if user:
            failure_counts[username] = 0
            session["username"] = username
            session["role"]     = user["role"]
            log_login(username, "SUCCESS", ip, f"Login successful from {ip}")
            log_session(username, ip)
            logging.info("LOGIN SUCCESS: %s from %s", username, ip)
            send_login_event(username, "SUCCESS", ip, f"Login successful from {ip}")
            send_session_event(username, ip, "login")
            return redirect(url_for("dashboard"))
        else:
            failure_counts[username] += 1
            count = failure_counts[username]
            log_login(username, "FAILED", ip, f"Wrong credentials (attempt {count})")
            logging.error("LOGIN FAILED: %s from %s (attempt %d)", username, ip, count)
            send_login_event(username, "FAILED", ip,
                             f"Wrong credentials (attempt {count})", attempt=count)
            if count >= BRUTE_THRESHOLD:
                lock_user(username)
                msg = f"BRUTE FORCE: {username} locked after {count} failed attempts from {ip}"
                logging.critical(msg)
                save_alert("brute_force", "CRITICAL", msg, username)
                send_brute_force(username, ip, count)
                elk_alert("brute_force", "CRITICAL", msg, username)
                error = f"Account locked after {count} failed attempts. Contact admin."
            else:
                error = f"Wrong username or password. Attempt {count} of {BRUTE_THRESHOLD}."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_login(username, "LOGOUT", request.remote_addr, "User logged out")
    log_session(username, request.remote_addr, logout_time=now)
    logging.info("LOGOUT: %s", username)
    send_login_event(username, "LOGOUT", request.remote_addr, "User logged out")
    send_session_event(username, request.remote_addr, "logout")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    es_status = check_es_connection()
    return render_template("dashboard.html",
                           username=session["username"], role=session["role"],
                           stats=get_stats(), alerts=get_alerts(10),
                           logs=get_login_logs(10), es_status=es_status)

@app.route("/logs")
def logs_page():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("logs.html", logs=get_login_logs(100),
                           username=session["username"], role=session.get("role","user"))

@app.route("/alerts")
def alerts_page():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("alerts.html", alerts=get_alerts(100),
                           username=session["username"], role=session.get("role","user"))

@app.route("/sessions")
def sessions_page():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("sessions.html", sessions=get_sessions(),
                           username=session["username"], role=session.get("role","user"))

@app.route("/users")
def users_page():
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        return redirect(url_for("dashboard"))
    return render_template("users.html", users=get_all_users(),
                           username=session["username"], role=session["role"])

@app.route("/users/add", methods=["POST"])
def add_user_route():
    if session.get("role") != "admin":
        return redirect(url_for("dashboard"))
    username = request.form.get("username","").strip()
    password = request.form.get("password","").strip()
    email    = request.form.get("email","").strip()
    role     = request.form.get("role","user")
    if username and password:
        success, msg = add_user(username, password, email, role)
        logging.info("USER ADD: %s by %s", username, session["username"])
        send_user_event("add_user", username, session["username"])
    return redirect(url_for("users_page"))

@app.route("/users/delete/<int:user_id>")
def delete_user_route(user_id):
    if session.get("role") != "admin":
        return redirect(url_for("dashboard"))
    delete_user(user_id)
    logging.info("USER DELETED: id=%d by %s", user_id, session["username"])
    send_user_event("delete_user", str(user_id), session["username"])
    return redirect(url_for("users_page"))

@app.route("/users/unlock/<username>")
def unlock_user_route(username):
    if session.get("role") != "admin":
        return redirect(url_for("dashboard"))
    unlock_user(username)
    logging.info("USER UNLOCKED: %s by %s", username, session["username"])
    send_user_event("unlock_user", username, session["username"])
    return redirect(url_for("users_page"))

@app.route("/api/stats")
def api_stats():
    if "username" not in session:
        return jsonify({"error":"unauthorized"}), 401
    stats = get_stats()
    stats["es_connected"] = check_es_connection()
    return jsonify(stats)

@app.route("/api/logs")
def api_logs():
    if "username" not in session:
        return jsonify({"error":"unauthorized"}), 401
    return jsonify(get_login_logs(20))

@app.route("/api/alerts")
def api_alerts():
    if "username" not in session:
        return jsonify({"error":"unauthorized"}), 401
    return jsonify(get_alerts(10))

if __name__ == "__main__":
    init_db()
    es_ok = check_es_connection()
    print("\n" + "="*60)
    print("  Cloud Monitor — Running!")
    print("  Flask  → http://localhost:5000")
    print("  Kibana → http://localhost:5601")
    print(f"  ELK    → {'CONNECTED' if es_ok else 'OFFLINE (start elk first)'}")
    print("="*60)
    print("  alice/password123  bob/securepass  admin/admin123")
    print("="*60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)