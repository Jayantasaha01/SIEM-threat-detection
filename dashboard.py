#!/usr/bin/env python3
from flask import Flask, render_template_string
import json, os, subprocess, time
from parser import parse_logs
from analyzer import detect_threats
from datetime import datetime

app = Flask(__name__)
collector_process = None
STOP_FILE = "collector.stop"

dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Mini SIEM Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: Arial; margin: 40px; }
        .alert { background: #ffdddd; padding: 10px; border-left: 5px solid red; margin-bottom: 10px; }
        h1 { color: #333; }
        .stop-btn { padding: 10px 20px; background: red; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>SIEM Security Events (Auto-Refreshing)</h1>
    <a class="stop-btn" href="/stop">Stop Collector & Dashboard</a>
    {% if events %}
        {% for e in events %}
            <div class="alert">
                <strong>Alert:</strong> {{ e.alert }} <br>
                <strong>IP:</strong> {{ e.src_ip }}<br>
                <strong>Time:</strong> {{ e.timestamp }}
            </div>
        {% endfor %}
    {% else %}
        <p>No security events detected.</p>
    {% endif %}
</body>
</html>
"""

@app.route("/")
def home():
    if os.path.exists("events.json"):
        with open("events.json") as f:
            events = json.load(f)
            for e in events:
                e['timestamp'] = datetime.fromtimestamp(e['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    else:
        events = []
    return render_template_string(dashboard_html, events=events)

@app.route("/stop")
def stop():
    # Create stop file to signal collector
    open(STOP_FILE, "w").close()
    time.sleep(1)  # wait for collector to exit
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)
    os._exit(0)  # terminate Flask

if __name__ == "__main__":
    # Start collector in background
    collector_process = subprocess.Popen(["python3", "collector.py"])
    time.sleep(2)

    # Parse and analyze logs
    logs = parse_logs("logs/sample_logs.json")
    events = detect_threats(logs)
    with open("events.json", "w") as f:
        json.dump(events, f, indent=2)

    # Start Flask dashboard
    app.run(host="0.0.0.0", port=5000, debug=True)