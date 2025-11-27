#!/usr/bin/env python3
from flask import Flask, render_template_string
import json, os, time, threading, webbrowser
from parser import parse_logs
from analyzer import detect_threats
from datetime import datetime
import collector

app = Flask(__name__)
STOP_FILE = os.path.join(os.getcwd(), "collector.stop")

# HTML template
dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Dashboard</title>
    <meta http-equiv="refresh" content="1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        h1 {
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            background: #10b981;
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
            box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        }
        
        @keyframes pulse {
            0%, 100% {
                box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
            }
            50% {
                box-shadow: 0 0 0 10px rgba(16, 185, 129, 0);
            }
        }
        
        .stop-btn {
            padding: 12px 24px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
            border: 1px solid rgba(239, 68, 68, 0.3);
            display: inline-block;
        }
        
        .stop-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(239, 68, 68, 0.3);
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: #60a5fa;
            margin-bottom: 8px;
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .events-section {
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 16px;
            padding: 30px;
        }
        
        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 24px;
            color: #f1f5f9;
        }
        
        .alert {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-left: 4px solid #ef4444;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 16px;
            transition: all 0.3s ease;
        }
        
        .alert:hover {
            transform: translateX(4px);
            background: rgba(239, 68, 68, 0.15);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.2);
        }
        
        .alert-content {
            display: grid;
            gap: 12px;
        }
        
        .alert-row {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .alert-label {
            font-weight: 600;
            color: #f87171;
            min-width: 80px;
        }
        
        .alert-value {
            color: #e2e8f0;
            font-family: 'Courier New', monospace;
        }
        
        .no-events {
            text-align: center;
            padding: 60px 20px;
            color: #64748b;
            font-size: 1.125rem;
        }
        
        .no-events::before {
            content: "✓";
            display: block;
            font-size: 4rem;
            color: #10b981;
            margin-bottom: 16px;
        }
        
        @media (max-width: 768px) {
            h1 {
                font-size: 1.5rem;
            }
            
            .header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .stats {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <span class="status-indicator"></span>
                SIEM Security Dashboard
            </h1>
            <a class="stop-btn" href="/stop">Stop Collector</a>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{{ events|length }}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">Live</div>
                <div class="stat-label">Status</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">1 Second</div>
                <div class="stat-label">Refresh Rate</div>
            </div>
        </div>
        
        <div class="events-section">
            <h2 class="section-title">Security Events</h2>
            {% if events %}
                {% for e in events %}
                    <div class="alert">
                        <div class="alert-content">
                            <div class="alert-row">
                                <span class="alert-label">Alert:</span>
                                <span class="alert-value">{{ e.alert }}</span>
                            </div>
                            <div class="alert-row">
                                <span class="alert-label">IP Address:</span>
                                <span class="alert-value">{{ e.src_ip }}</span>
                            </div>
                            <div class="alert-row">
                                <span class="alert-label">Timestamp:</span>
                                <span class="alert-value">{{ e.timestamp }}</span>
                            </div>
                        </div>
                    </div>
                {% endfor %}
            {% else %}
                <div class="no-events">
                    No security events detected
                </div>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def home():
    # Parse and analyze logs on each request for real-time updates
    if os.path.exists("logs/logs.json"):
        logs = parse_logs("logs/logs.json")
        events = detect_threats(logs)
        
        # Save events to JSON file
        with open("events.json", "w") as f:
            json.dump(events, f, indent=2)
        
        # Format timestamps for display
        for e in events:
            e['timestamp'] = datetime.fromtimestamp(e['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    else:
        events = []
    
    return render_template_string(dashboard_html, events=events)

@app.route("/stop")
def stop():
    # Signal collector to stop
    open(STOP_FILE, "w").close()
    time.sleep(2)
    if os.path.exists(STOP_FILE):
        os.remove(STOP_FILE)
    os._exit(0)

def run_collector():
    collector.main_loop()

if __name__ == "__main__":
    # Start collector in a separate thread
    collector_thread = threading.Thread(target=run_collector, daemon=True)
    collector_thread.start()
   # allow collector to generate logs
    time.sleep(2)  
# Open browser automatically (only on first run, not on reloader)
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        threading.Timer(1.5, lambda: webbrowser.open('http://localhost:8080')).start()
    # Run Flask dashboard
    app.run(host="0.0.0.0", port=8080, debug=True)
