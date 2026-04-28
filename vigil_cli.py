#!/usr/bin/env python3
"""
Vigil CLI — inspect session audit logs.

Usage:
  python vigil_cli.py report <session_id>       # Print markdown report
  python vigil_cli.py list                       # List all sessions
  python vigil_cli.py findings <session_id>      # Print only BLOCK findings
  python vigil_cli.py stats <session_id>         # Print stats summary
"""

import sys
import json
from pathlib import Path
from audit.report import generate_report

LOG_DIR = "logs"

def cmd_report(session_id: str):
    print(generate_report(session_id, LOG_DIR))

def cmd_list():
    log_dir = Path(LOG_DIR)
    if not log_dir.exists():
        print("No logs directory found.")
        return
    sessions = sorted(log_dir.glob("session_*.jsonl"))
    if not sessions:
        print("No sessions found.")
        return
    print(f"{'Session ID':<20} {'Started':<30} {'Calls':<8} {'Blocks'}")
    print("-" * 70)
    for path in sessions:
        session_id = path.stem.replace("session_", "")
        events = []
        for l in path.read_text().strip().splitlines():
            if l:
                try:
                    events.append(json.loads(l))
                except json.JSONDecodeError:
                    pass
        start = next((e.get("timestamp", "-") for e in events if e.get("event") == "session_start"), "-")
        calls = sum(1 for e in events if e.get("event") == "tool_call")
        blocks = sum(1 for e in events if e.get("event") == "tool_call" and e.get("verdict") in ("BLOCK", "CLEAR_BLOCK"))
        print(f"{session_id:<20} {start:<30} {calls:<8} {blocks}")

def cmd_findings(session_id: str):
    log_path = Path(LOG_DIR) / f"session_{session_id}.jsonl"
    if not log_path.exists():
        print(f"Session {session_id} not found.")
        return
    events = []
    for l in log_path.read_text().strip().splitlines():
        if l:
            try:
                events.append(json.loads(l))
            except json.JSONDecodeError:
                pass
    findings = [e for e in events if e.get("event") == "tool_call" and e.get("verdict") in ("BLOCK", "CLEAR_BLOCK")]
    if not findings:
        print("No findings in this session.")
        return
    for f in findings:
        print(f"\nCall #{f.get('call_id', '?')} — {f.get('verdict')} ({f.get('severity', 'UNKNOWN')})")
        print(f"  File: {f.get('file')}")
        print(f"  Finding: {f.get('finding')}")
        print(f"  Fix: {f.get('fix')}")

def cmd_stats(session_id: str):
    log_path = Path(LOG_DIR) / f"session_{session_id}.jsonl"
    if not log_path.exists():
        print(f"Session {session_id} not found.")
        return
    events = []
    for l in log_path.read_text().strip().splitlines():
        if l:
            try:
                events.append(json.loads(l))
            except json.JSONDecodeError:
                pass
    calls = [e for e in events if e.get("event") == "tool_call"]
    verdicts = {}
    for e in calls:
        v = e.get("verdict", "UNKNOWN")
        verdicts[v] = verdicts.get(v, 0) + 1
    print(f"Session: {session_id}")
    print(f"Total calls: {len(calls)}")
    for verdict, count in sorted(verdicts.items()):
        print(f"  {verdict}: {count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "report" and len(sys.argv) == 3:
        cmd_report(sys.argv[2])
    elif cmd == "list":
        cmd_list()
    elif cmd == "findings" and len(sys.argv) == 3:
        cmd_findings(sys.argv[2])
    elif cmd == "stats" and len(sys.argv) == 3:
        cmd_stats(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)
