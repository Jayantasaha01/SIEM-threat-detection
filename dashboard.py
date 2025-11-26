#!/usr/bin/env python3
from flask import Flask, render_template_string
import json, os, subprocess, time
from parser import parse_logs
from analyzer import detect_threats

app = Flask(__name__)

dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Mini SIEM Dashboard</title>
    <meta http-equiv=\"refresh\" content=\"5\"> <!-- Auto-refresh every 5 seconds -->
    <style>
        body { font-family: Arial; margin: 40px; }
        .alert { background: #ffdddd; padding: 10px; border-left: 5px solid red; margin-bottom: 10px; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>SIEM Security Events (Auto-Refreshing)</h1>
    {% if events %}
        {% for e in events %}
            <div class=\"alert\">
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
    else:
        events = []
    return render_template_string(dashboard_html, events=events)

if __name__ == "__main__":
    # Start collector in the background
    collector_process = subprocess.Popen(["python3", "collector.py"])
    time.sleep(2)  # Give collector time to generate logs

    # Parse and analyze logs
    logs = parse_logs("logs/sample_logs.json")
    events = detect_threats(logs)
    with open("events.json", "w") as f:
        json.dump(events, f, indent=2)

    # Start Flask dashboard
    app.run(host="0.0.0.0", port=5000, debug=True)