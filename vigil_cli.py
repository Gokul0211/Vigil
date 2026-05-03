#!/usr/bin/env python3
"""
Vigil CLI — inspect session audit logs.

Usage:
  python vigil_cli.py report <session_id>       # Print markdown report
  python vigil_cli.py list                       # List all sessions
  python vigil_cli.py findings <session_id>      # Print only BLOCK findings
  python vigil_cli.py stats <session_id>         # Print stats summary
  python vigil_cli.py warns <session_id>                          # WARN findings only
  python vigil_cli.py export-dataset <session_id> [--negatives]   # Export fine-tuning dataset
  python vigil_cli.py verify <session_id> [project_root]          # Verify ASSUMES against codebase
  python vigil_cli.py check-brief "prompt text"                   # Validate brief generation from prompt
"""

import sys
import json
import os
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

def cmd_export_dataset(session_id: str, out_path: str | None = None, include_negatives: bool = False):
    from audit.dataset import generate_dataset
    try:
        result = generate_dataset(session_id, out_path=out_path, include_negatives=include_negatives)
        if result.endswith(".jsonl"):
            print(f"Dataset exported to: {result}")
            # Count records
            with open(result) as f:
                count = sum(1 for line in f if line.strip())
            print(f"Records: {count}")
        else:
            print(result)
    except FileNotFoundError as e:
        print(str(e))

def cmd_check_brief(prompt_text: str):
    import asyncio
    from brief.generator import generate_brief, validate_brief
    print("[Vigil] Generating brief...")
    brief = asyncio.run(generate_brief(prompt_text))
    issues = validate_brief(brief)
    
    print("\n--- Generated Brief Preview ---")
    print("\n".join(brief.raw_markdown.splitlines()[:15]) + "\n...")
    print("-------------------------------\n")
    
    if issues:
        print(f"[Vigil] {len(issues)} quality issue(s) found:")
        for i in issues:
            print(f"  - {i}")
        print("\n[Vigil] Brief generation failed quality checks.")
    else:
        print("[Vigil] Brief generation passed all quality checks.")

def cmd_warn_summary(session_id: str):
    """Print only WARN findings for a session."""
    log_path = Path(LOG_DIR) / f"session_{session_id}.jsonl"
    if not log_path.exists():
        print(f"Session {session_id} not found.")
        return
    events = [json.loads(l) for l in log_path.read_text().strip().splitlines() if l]
    warns = [e for e in events if e["event"] == "tool_call" and e.get("verdict") == "WARN"]
    if not warns:
        print("No warnings in this session.")
        return
    for w in warns:
        print(f"\nCall #{w['call_id']} — WARN ({w.get('severity', 'UNKNOWN')})")
        print(f"  File: {w.get('file')}")
        print(f"  Finding: {w.get('finding')}")

def cmd_verify(session_id: str, project_root: str | None = None):
    """Run ASSUMES verification for a session against the codebase."""
    import asyncio
    from audit.verifier import verify_assumptions, format_verification_report

    print(f"[Vigil] Running ASSUMES verification for session {session_id}...")
    print(f"[Vigil] Project root: {project_root or os.getcwd()}")

    try:
        results = asyncio.run(verify_assumptions(
            session_id=session_id,
            project_root=project_root,
            log_dir=LOG_DIR
        ))
    except FileNotFoundError as e:
        print(str(e))
        return

    report = format_verification_report(results, session_id)
    print(report)

    unverified = [r for r in results if r.status == "UNVERIFIED"]
    if unverified:
        print(f"\n[Vigil] {len(unverified)} unverified assumption(s) found.")
        print("[Vigil] These are architectural promises that were never implemented.")

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
    elif cmd == "export-dataset" and len(sys.argv) >= 3:
        session = sys.argv[2]
        include_negatives = "--negatives" in sys.argv
        
        args = [a for a in sys.argv[3:] if a != "--negatives"]
        out = args[0] if len(args) > 0 else None
        cmd_export_dataset(session, out, include_negatives=include_negatives)
    elif cmd == "warns" and len(sys.argv) == 3:
        cmd_warn_summary(sys.argv[2])
    elif cmd == "verify" and len(sys.argv) >= 3:
        root = sys.argv[3] if len(sys.argv) >= 4 else None
        cmd_verify(sys.argv[2], root)
    elif cmd == "check-brief" and len(sys.argv) == 3:
        cmd_check_brief(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)
