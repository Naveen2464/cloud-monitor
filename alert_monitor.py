import time, os, smtplib, logging
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from collections import defaultdict
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

LOG_FILE  = "app.log"
ALERT_LOG = "alerts.log"
SENDER    = os.getenv("SENDER_EMAIL", "")
RECEIVER  = os.getenv("RECEIVER_EMAIL", "")
PASSWORD  = os.getenv("APP_PASSWORD", "")
COOLDOWN  = 60

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [MONITOR] %(levelname)s %(message)s")
logger    = logging.getLogger("monitor")
last_sent = defaultdict(lambda: datetime.min)

def can_send(key):
    if datetime.now() - last_sent[key] > timedelta(seconds=COOLDOWN):
        last_sent[key] = datetime.now()
        return True
    return False

def send_email(subject, body):
    if not all([SENDER, RECEIVER, PASSWORD]):
        logger.warning("Email not configured")
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = SENDER
        msg["To"]      = RECEIVER
        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.starttls()
            s.login(SENDER, PASSWORD)
            s.sendmail(SENDER, RECEIVER, msg.as_string())
        logger.info("Email sent: %s", subject)
    except Exception as e:
        logger.error("Email error: %s", e)

def write_alert_log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERT_LOG, "a") as f:
        f.write(f"[{ts}] {msg}\n")

def process_line(line):
    line = line.strip()
    if not line: return
    if "BRUTE FORCE" in line:
        write_alert_log(line)
        logger.critical("BRUTE FORCE: %s", line)
        if can_send("brute_force"):
            send_email("CRITICAL: Brute Force Detected", line)
    elif "LOGIN FAILED" in line:
        write_alert_log(line)
        logger.warning("LOGIN FAILED: %s", line)
        if can_send("login_failed"):
            send_email("WARNING: Login Failure", line)

def monitor():
    logger.info("=== Alert Monitor Started ===")
    while not os.path.exists(LOG_FILE):
        time.sleep(2)
    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            if any(k in line for k in ["ERROR","CRITICAL","WARNING"]):
                process_line(line)

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        logger.info("=== Monitor Stopped ===")