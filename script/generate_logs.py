import os
import json
import random
import datetime

# Ensure logs folder exists
LOG_DIR = "../logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Output files
AUTH_LOG = os.path.join(LOG_DIR, "auth.log")
WINDOWS_LOG = os.path.join(LOG_DIR, "windows_events.json")
NETWORK_LOG = os.path.join(LOG_DIR, "network_traffic.log")

users = ["alice", "bob", "charlie", "david", "admin", "svc_backup"]
ips = [
    "10.0.0.5", "10.0.0.8", "10.0.0.11",
    "203.0.113.45",  # malicious IP
    "198.51.100.22",  # suspicious
]
hosts = ["web01", "web02", "workstation01", "dc01"]

event_types = [
    "login_success",
    "login_failure",
    "file_modified",
    "privilege_escalation",
    "process_start",
    "network_connection",
    "suspicious_command"
]

def random_timestamp():
    """Return ISO UTC timestamp."""
    return datetime.datetime.utcnow().isoformat() + "Z"


# ---------- GENERATE AUTH.LOG (Linux style) ----------
def generate_auth_log():
    with open(AUTH_LOG, "w") as f:
        for _ in range(500):
            event = random.choice(["Accepted password", "Failed password"])
            user = random.choice(users)
            ip = random.choice(ips)
            timestamp = datetime.datetime.utcnow().strftime("%b %d %H:%M:%S")

            log_line = f"{timestamp} sshd[1234]: {event} for {user} from {ip} port 22 ssh2\n"
            f.write(log_line)

        # Inject brute force attacks
        for _ in range(30):
            log_line = f"{timestamp} sshd[1234]: Failed password for invalid user hacker from 203.0.113.45 port 22 ssh2\n"
            f.write(log_line)


# ---------- GENERATE WINDOWS SECURITY LOG (JSON) ----------
def generate_windows_log():
    logs = []
    for _ in range(400):
        log = {
            "timestamp": random_timestamp(),
            "host": random.choice(hosts),
            "event_id": random.choice([4624, 4625, 4648, 4672, 4688]),
            "user": random.choice(users),
            "ip_address": random.choice(ips),
            "action": random.choice(event_types)
        }
        logs.append(log)

    # Inject privilege escalation events
    for _ in range(10):
        logs.append({
            "timestamp": random_timestamp(),
            "host": "dc01",
            "event_id": 4672,
            "user": "admin",
            "ip_address": "203.0.113.45",
            "action": "privilege_escalation"
        })

    with open(WINDOWS_LOG, "w") as f:
        json.dump(logs, f, indent=4)


# ---------- GENERATE NETWORK TRAFFIC LOG ----------
def generate_network_log():
    with open(NETWORK_LOG, "w") as f:
        for _ in range(300):
            ts = random_timestamp()
            src = random.choice(ips)
            dst = random.choice(["10.0.0.5", "10.0.0.8", "10.0.0.12"])
            event = random.choice(["ALLOW", "DENY", "SCAN", "SUSPICIOUS_TRAFFIC"])

            log_line = f"{ts} SRC={src} DST={dst} ACTION={event}\n"
            f.write(log_line)

        # Inject port scan attack
        for port in range(1, 50):
            log_line = f"{random_timestamp()} SRC=203.0.113.45 DST=10.0.0.5 ACTION=SCAN PORT={port}\n"
            f.write(log_line)


# ---------- MAIN ----------
if __name__ == "__main__":
    print("Generating log files...")
    generate_auth_log()
    generate_windows_log()
    generate_network_log()
    print(f"Logs generated in: {LOG_DIR}")
