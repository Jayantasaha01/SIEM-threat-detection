#!/usr/bin/env python3
import json, time, random, os

IPS = ["192.168.1.15", "10.0.0.5", "203.0.113.45", "198.51.100.77"]
EVENTS = ["login_success", "login_failed", "file_access", "network_scan"]

os.makedirs("logs", exist_ok=True)

# Run continuously and append logs
while True:
    log = {
        "timestamp": time.time(),
        "src_ip": random.choice(IPS),
        "event": random.choice(EVENTS)
    }
    with open("logs/sample_logs.json", "a") as f:
        f.write(json.dumps(log) + "\n")
    time.sleep(1)