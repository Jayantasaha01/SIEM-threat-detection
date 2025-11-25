# scripts/generate_logs.py
import random, time, json, datetime

hosts = ["web01.example.com","web02.example.com","workstation01.example.com"]
ips = ["10.0.0.5","10.0.0.10","198.51.100.22","203.0.113.45"]
users = ["alice","bob","charlie","svc_backup","admin"]

events = [
  {"event":"login_success"},
  {"event":"login_failure"},
  {"event":"privilege_escalation"},
  {"event":"file_download"},
  {"event":"suspicious_command"}
]

def rand_event():
    e = random.choice(events)
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    return {
        "timestamp": timestamp,
        "host": random.choice(hosts),
        "src_ip": random.choice(ips),
        "user": random.choice(users),
        "event": e["event"],
        "detail": ""
    }

def inject_suspicious():
    return {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "host": "web01.example.com",
        "src_ip": "203.0.113.45",
        "user": "unknown",
        "event": "brute_force_attempt",
        "detail": "Multiple failed logins"
    }

if __name__ == "__main__":
    fname = "../logs/sample_syslog.log"
    with open(fname, "w") as f:
        for i in range(1200):
            if random.random() < 0.02:
                e = inject_suspicious()
            else:
                e = rand_event()
            f.write(json.dumps(e) + "\n")
    print("Wrote", fname)
