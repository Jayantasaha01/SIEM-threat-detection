#!/usr/bin/env python3
import json

def parse_logs(input_file):
    parsed = []
    with open(input_file) as f:
        for line in f:
            try:
                log = json.loads(line)
                parsed.append(log)
            except:
                continue
    return parsed

if __name__ == "__main__":
    logs = parse_logs("logs/sample_logs.json")
    print(f"Parsed {len(logs)} logs.")
