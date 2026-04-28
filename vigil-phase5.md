# Vigil — Phase 5: Audit Report, CLI, Integration & End-to-End Testing

## What This Phase Builds

Vigil is functionally complete after Phase 4. Phase 5 makes it usable and verifiable:
- Session audit report generator — readable summary of every security decision in a session
- CLI tool — inspect logs, replay sessions, query findings
- CLAUDE.md template — drop-in integration instructions for Claude Code
- Invariant violation tracker — session-level summary of which invariants were touched
- End-to-end test suite — scripted scenarios that exercise the full pipeline
- README with setup instructions

By end of this phase, Vigil is ready to be used on a real project.

---

## Prerequisites

Phase 4 complete. Full interceptor working. Tier 2 async + pending_block injection working. All prior tests passing.

---

## Audit Report Generator — `audit/report.py`

Reads the JSONL audit log for a session and produces a readable markdown report. Useful after a coding session to review what Vigil caught, approved, and deferred.

```python
import json
from pathlib import Path
from datetime import datetime

def generate_report(session_id: str, log_dir: str = "logs") -> str:
    """
    Reads the JSONL log for a session and produces a markdown audit report.
    Returns the report as a string.
    """
    log_path = Path(log_dir) / f"session_{session_id}.jsonl"
    if not log_path.exists():
        return f"No log found for session {session_id}"

    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    return _format_report(session_id, events)


def _format_report(session_id: str, events: list[dict]) -> str:
    lines = []
    lines.append(f"# Vigil Session Report — {session_id}")
    lines.append("")

    # Session metadata
    start_event = next((e for e in events if e["event"] == "session_start"), None)
    if start_event:
        lines.append(f"**Started:** {start_event.get('timestamp', 'unknown')}")
    lines.append("")

    # Brief preview
    brief_event = next((e for e in events if e["event"] == "brief_generated"), None)
    if brief_event:
        lines.append("## Architecture Brief (Preview)")
        lines.append(f"```")
        lines.append(brief_event.get("brief_preview", "")[:500])
        lines.append(f"```")
        lines.append("")

    # Tool call summary
    tool_calls = [e for e in events if e["event"] == "tool_call"]
    if not tool_calls:
        lines.append("No tool calls recorded.")
        return "\n".join(lines)

    # Stats
    total = len(tool_calls)
    blocked = [e for e in tool_calls if e.get("verdict") in ("BLOCK", "CLEAR_BLOCK")]
    approved = [e for e in tool_calls if e.get("verdict") in ("APPROVE", "CLEAR_PASS")]
    ambiguous = [e for e in tool_calls if e.get("verdict") == "AMBIGUOUS"]
    skipped = [e for e in tool_calls if e.get("verdict") == "SKIP"]
    malformed = [e for e in tool_calls if e.get("malformed_intent")]

    lines.append("## Summary")
    lines.append(f"| Metric | Count |")
    lines.append(f"|---|---|")
    lines.append(f"| Total tool calls | {total} |")
    lines.append(f"| Approved | {len(approved)} |")
    lines.append(f"| Blocked | {len(blocked)} |")
    lines.append(f"| Ambiguous (Tier 2 routed) | {len(ambiguous)} |")
    lines.append(f"| Skipped (not security relevant) | {len(skipped)} |")
    lines.append(f"| Malformed INTENT (inferred) | {len(malformed)} |")
    lines.append("")

    # Findings (BLOCK only)
    if blocked:
        lines.append("## Security Findings")
        lines.append("")
        for e in blocked:
            lines.append(f"### Call #{e['call_id']} — {e.get('verdict')} ({e.get('severity', 'UNKNOWN')})")
            lines.append(f"**File:** `{e.get('file', 'unknown')}`")
            lines.append(f"**Tool:** {e.get('tool', 'unknown')}")
            intent = e.get("intent", {})
            lines.append(f"**Intent:** {intent.get('intent', '-')}")
            lines.append(f"**Finding:** {e.get('finding', 'No details')}")
            if e.get("fix"):
                lines.append(f"**Fix:** {e['fix']}")
            if e.get("invariant_violated"):
                lines.append(f"**Invariant violated:** `{e['invariant_violated']}`")
            lines.append(f"**Timestamp:** {e.get('timestamp', '-')}")
            lines.append("")

    # Malformed INTENT summary
    malformed_events = [e for e in events if e["event"] == "malformed_intent"]
    if malformed_events:
        lines.append("## Malformed INTENT Signals")
        lines.append("")
        lines.append("These calls had empty or garbage INTENT fields. Security relevance was inferred from the diff.")
        lines.append("")
        for e in malformed_events:
            lines.append(f"- Call #{e.get('call_id')}: `{e.get('file', '-')}` — {e.get('reason', '-')}")
        lines.append("")

    # Invariant status
    invariant_violations = set(
        e["invariant_violated"]
        for e in tool_calls
        if e.get("invariant_violated")
    )
    if invariant_violations:
        lines.append("## Invariant Violations")
        for inv in sorted(invariant_violations):
            lines.append(f"- ❌ `{inv}`")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by Vigil at {datetime.utcnow().isoformat()}*")

    return "\n".join(lines)
```

---

## CLI Tool — `vigil_cli.py`

A simple CLI for working with session logs. Lives at project root.

```python
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
        events = [json.loads(l) for l in path.read_text().strip().splitlines() if l]
        start = next((e.get("timestamp", "-") for e in events if e["event"] == "session_start"), "-")
        calls = sum(1 for e in events if e["event"] == "tool_call")
        blocks = sum(1 for e in events if e["event"] == "tool_call" and e.get("verdict") in ("BLOCK", "CLEAR_BLOCK"))
        print(f"{session_id:<20} {start:<30} {calls:<8} {blocks}")

def cmd_findings(session_id: str):
    log_path = Path(LOG_DIR) / f"session_{session_id}.jsonl"
    if not log_path.exists():
        print(f"Session {session_id} not found.")
        return
    events = [json.loads(l) for l in log_path.read_text().strip().splitlines() if l]
    findings = [e for e in events if e["event"] == "tool_call" and e.get("verdict") in ("BLOCK", "CLEAR_BLOCK")]
    if not findings:
        print("No findings in this session.")
        return
    for f in findings:
        print(f"\nCall #{f['call_id']} — {f['verdict']} ({f.get('severity', 'UNKNOWN')})")
        print(f"  File: {f.get('file')}")
        print(f"  Finding: {f.get('finding')}")
        print(f"  Fix: {f.get('fix')}")

def cmd_stats(session_id: str):
    log_path = Path(LOG_DIR) / f"session_{session_id}.jsonl"
    if not log_path.exists():
        print(f"Session {session_id} not found.")
        return
    events = [json.loads(l) for l in log_path.read_text().strip().splitlines() if l]
    calls = [e for e in events if e["event"] == "tool_call"]
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
```

---

## CLAUDE.md Template

Drop this in the root of any project that uses Vigil. Claude Code reads `CLAUDE.md` before every session.

```markdown
# Vigil Integration

This project uses **Vigil** — a real-time security watcher that intercepts file writes
and analyzes them for security issues before they land.

## File Writing Tools

You have access to three file-writing tools provided by Vigil. **You must use these
instead of the standard write_file, str_replace, and create_file tools.**

- `vigil_write_file` — replaces `write_file`
- `vigil_str_replace` — replaces `str_replace`
- `vigil_create_file` — replaces `create_file`

## Required Parameters

Every Vigil tool call requires these additional parameters:

| Parameter | Type | What to put |
|---|---|---|
| `intent` | string | One sentence: what does this code block do? |
| `reason` | string | Why is this decision being made? |
| `affects` | list[str] | Which security domains does this touch? |
| `invariants_touched` | list[str] | Any invariants from the brief being relaxed? |
| `assumes` | list[str] | Any external guarantees being relied on? |

**Valid `affects` values:** `auth`, `crypto`, `logging`, `data-exposure`,
`input-validation`, `file-system`, `network`, `none`

Set `affects=[]`, `invariants_touched=[]`, and `assumes=[]` explicitly if none apply.
Do **not** omit them.

## Examples

```python
# Creating a route that touches auth
vigil_create_file(
    path="src/routes/checkout.py",
    file_text="...",
    intent="implementing checkout route with JWT validation",
    reason="core payment flow per architecture brief",
    affects=["auth", "data-exposure"],
    invariants_touched=[],
    assumes=["JWT middleware active on /api/v1/ routes"]
)

# A pure logic change with no security implications
vigil_str_replace(
    path="src/utils/formatting.py",
    old_str="def format_price(p): return p",
    new_str="def format_price(p): return f'${p:.2f}'",
    intent="formatting price display",
    reason="UX improvement",
    affects=[],
    invariants_touched=[],
    assumes=[]
)
```

## Vigil Responses

Vigil will respond to every tool call with one of:

- `[Vigil] APPROVE` — proceed normally
- `[Vigil] SKIP` — not security relevant, proceeded
- `[Vigil] BLOCK` — violation found, **file was NOT written**, you must fix before continuing
- `[Vigil] AMBIGUOUS` — file written, deep analysis running in background
- `[Vigil] DEFERRED BLOCK` — a prior async finding requires your attention **before proceeding**

When you receive a BLOCK or DEFERRED BLOCK, read the finding carefully and address it
before making any further file changes.
```

---

## End-to-End Test Scenarios — `tests/test_e2e.py`

These are scripted scenarios that exercise the full pipeline. Use monkeypatching to control Tier 1/2 responses — you don't want real API calls in CI.

```python
import pytest
import asyncio
from unittest.mock import patch
from models.verdict import Verdict
from models.intent import IntentMessage


def make_intent(**kwargs):
    defaults = {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []}
    defaults.update(kwargs)
    return IntentMessage(**defaults)


async def make_interceptor(tmp_path, brief_md=None):
    from brief.generator import _parse_brief
    from server.interceptor import Interceptor
    from server.context import ContextManager
    from audit.logger import AuditLogger

    if brief_md is None:
        brief_md = """# Architecture Brief
## System Purpose
Payment service.
## Trust Boundaries
- PUBLIC: /api/v1/*
- INTERNAL ONLY: /api/internal/*, /admin/*
## Auth Model
JWT on all /api/v1/ routes. Internal routes behind VPC.
## Data Flows
- User input -> validation -> DB
- Payment data never logged
## Security Invariants
- [ ] no-pii-in-logs: Payment data must never appear in logs
- [ ] admin-role-required: /admin/* never reachable without role=admin
- [ ] no-hardcoded-secrets: No secrets hardcoded in source
## Sensitive Operations
- DB writes
- Payment API calls
"""
    brief = _parse_brief(brief_md)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="e2e", log_dir=str(tmp_path))
    return Interceptor(brief=brief, context=ctx, logger=logger, session_id="e2e")


# ---- Scenario 1: Hardcoded secret → immediate BLOCK ----

@pytest.mark.asyncio
async def test_scenario_hardcoded_secret_blocked(tmp_path, monkeypatch):
    """A file with a hardcoded secret is blocked by Tier 1. File not written."""
    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="CLEAR_BLOCK", severity="CRITICAL",
                              finding="Hardcoded API key", fix="Use env var",
                              invariant_violated="no-hardcoded-secrets")
    )

    target = tmp_path / "config.py"
    result = await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": 'SECRET = "sk-hardcoded"'},
        intent_raw=make_intent(affects=["auth"]).model_dump()
    )

    assert "BLOCK" in result
    assert "Hardcoded API key" in result
    assert not target.exists()


# ---- Scenario 2: Clean code → APPROVE ----

@pytest.mark.asyncio
async def test_scenario_clean_code_approved(tmp_path, monkeypatch):
    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="CLEAR_PASS")
    )

    target = tmp_path / "utils.py"
    result = await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": "def add(a, b): return a + b"},
        intent_raw=make_intent(affects=["none"]).model_dump()
    )

    assert "APPROVE" in result
    assert target.exists()


# ---- Scenario 3: Business logic flaw caught by Tier 2 ----

@pytest.mark.asyncio
async def test_scenario_tier2_deferred_block(tmp_path, monkeypatch):
    """
    Call #1: AMBIGUOUS → Tier 2 runs, finds auth bypass
    Call #2: DEFERRED BLOCK injected, file NOT written
    """
    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="AMBIGUOUS")
    )

    block = Verdict(
        verdict="BLOCK", severity="HIGH",
        vulnerability_class="business-logic/auth-bypass",
        finding="VPC assumption unverified — no network policy in codebase",
        fix="Add VPC config or explicit auth check",
        invariant_violated="admin-role-required"
    )

    async def mock_tier2(**kw):
        return block

    monkeypatch.setattr("server.interceptor.analyze_async", mock_tier2)

    # Call #1
    f1 = tmp_path / "internal.py"
    r1 = await interceptor.handle(
        tool="vigil_create_file", file_path=str(f1),
        params={"path": str(f1), "file_text": "def health(): return 'ok'"},
        intent_raw=make_intent(affects=["auth"], assumes=["VPC enforces auth"]).model_dump()
    )
    assert "AMBIGUOUS" in r1
    assert f1.exists()

    await asyncio.sleep(0.1)

    # Call #2 — should get deferred block
    f2 = tmp_path / "next.py"
    r2 = await interceptor.handle(
        tool="vigil_create_file", file_path=str(f2),
        params={"path": str(f2), "file_text": "x = 1"},
        intent_raw=make_intent().model_dump()
    )
    assert "DEFERRED BLOCK" in r2
    assert "VPC assumption unverified" in r2
    assert not f2.exists()


# ---- Scenario 4: PII in logs → Tier 1 BLOCK ----

@pytest.mark.asyncio
async def test_scenario_pii_in_logs(tmp_path, monkeypatch):
    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="CLEAR_BLOCK", severity="HIGH",
                              finding="PII written to log call",
                              fix="Remove card number from log",
                              invariant_violated="no-pii-in-logs")
    )

    target = tmp_path / "payment.py"
    result = await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": 'logger.info(f"Processing {card_number}")'},
        intent_raw=make_intent(affects=["logging", "data-exposure"]).model_dump()
    )

    assert "BLOCK" in result
    assert "no-pii-in-logs" in result
    assert not target.exists()


# ---- Scenario 5: Irrelevant utility code → SKIP ----

@pytest.mark.asyncio
async def test_scenario_utility_code_skipped(tmp_path):
    """Pure utility code with no security keywords — should be SKIPped without Tier 1 call."""
    interceptor = await make_interceptor(tmp_path)

    target = tmp_path / "math_utils.py"
    result = await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": "def clamp(v, lo, hi): return max(lo, min(hi, v))"},
        intent_raw=make_intent(affects=[]).model_dump()
    )

    assert "SKIP" in result
    assert target.exists()  # file written despite skip


# ---- Scenario 6: Empty INTENT → inferred, still routed to Tier 1 ----

@pytest.mark.asyncio
async def test_scenario_empty_intent_inferred(tmp_path, monkeypatch):
    interceptor = await make_interceptor(tmp_path)

    tier1_called = {"called": False}

    def mock_tier1(**kw):
        tier1_called["called"] = True
        return Verdict(verdict="CLEAR_PASS")

    monkeypatch.setattr("server.interceptor.analyze_sync", mock_tier1)

    target = tmp_path / "auth.py"
    await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": "token = jwt.decode(auth_header, SECRET)"},
        intent_raw=make_intent(affects=[]).model_dump()  # empty affects
    )

    assert tier1_called["called"]  # should have been routed despite empty affects


# ---- Scenario 7: Audit report generation ----

@pytest.mark.asyncio
async def test_scenario_audit_report(tmp_path, monkeypatch):
    from audit.report import generate_report

    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="CLEAR_BLOCK", severity="HIGH",
                              finding="SQL injection", fix="Use parameterized queries")
    )

    target = tmp_path / "query.py"
    await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": 'db.execute(f"SELECT * FROM users WHERE id={uid}")'},
        intent_raw=make_intent(affects=["input-validation"]).model_dump()
    )

    report = generate_report("e2e", log_dir=str(tmp_path))
    assert "SQL injection" in report
    assert "BLOCK" in report
    assert "Security Findings" in report
```

---

## Final README Sections to Write

Add these sections to `README.md`:

```markdown
## Quick Start

### 1. Install
pip install -r requirements.txt

### 2. Configure
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and VIGIL_PROJECT_PROMPT

### 3. Add to Claude Code
Add to .mcp.json in your project root:
{
  "mcpServers": {
    "vigil": {
      "command": "python",
      "args": ["<path_to_vigil>/server/main.py"],
      "env": {
        "VIGIL_PROJECT_PROMPT": "your project description",
        "ANTHROPIC_API_KEY": "your key"
      }
    }
  }
}

Copy CLAUDE.md template into your project root.

### 4. Start Coding
Claude Code will automatically use vigil_* tools for all file writes.

---

## CLI

python vigil_cli.py list                    # List all sessions
python vigil_cli.py report <session_id>     # Full markdown report
python vigil_cli.py findings <session_id>   # Only BLOCK findings
python vigil_cli.py stats <session_id>      # Summary stats

---

## Running Tests

pytest                        # All tests
pytest tests/test_models.py   # Phase 1: schemas only
pytest tests/test_phase2.py   # Phase 2: MCP server + brief gen
pytest tests/test_phase3.py   # Phase 3: classifier + Tier 1
pytest tests/test_phase4.py   # Phase 4: Tier 2 + pending_block
pytest tests/test_e2e.py      # Phase 5: full pipeline scenarios
```

---

## Completion Criteria for Phase 5

- [ ] `pytest tests/test_e2e.py` passes fully — all 7 scenarios
- [ ] Full test suite passes: `pytest` — no failures across all phases
- [ ] `python vigil_cli.py list` works and shows real sessions
- [ ] `python vigil_cli.py report <id>` produces readable markdown with findings, stats, invariant violations
- [ ] `python vigil_cli.py findings <id>` prints only BLOCK entries
- [ ] CLAUDE.md template is complete and correct
- [ ] README quick-start works from scratch on a clean clone
- [ ] Manual end-to-end test with a real Claude Code session:
  - Connect Claude Code via `.mcp.json`
  - Build a 10-file project with at least one deliberate auth bypass
  - Verify Vigil catches the bypass (Tier 1 or Tier 2)
  - Run `vigil_cli.py report` and verify the finding appears

---

## Post-MVP: What to Build Next (V1 Roadmap)

Document these in `README.md` under "Roadmap" so they're tracked:

1. **Interactive brief review** — before the session starts, show the generated brief and let the user edit invariants before any coding begins. Brief quality is the critical variable.

2. **Structured invariant tracking** — instead of invariant IDs as free strings, link them to `SecurityInvariant` objects. Track satisfied/violated state per session. Show a live invariant dashboard.

3. **ASSUMES verification pass** — at session end, for every `assumes` field across all calls, cross-check: is there code in the session that actually implements that assumption? If not, flag it.

4. **Override mechanism** — let the user confirm a BLOCK and proceed anyway (with a required justification). Log the override with full context. Useful for deliberate invariant relaxation.

5. **Fine-tuning dataset collection** — every AMBIGUOUS → (BLOCK or APPROVE) pair from Tier 2 is a labeled training example. Collect these in a separate JSONL file. After enough sessions, use them to fine-tune Tier 1 to resolve more cases without reaching Tier 2.

6. **Severity thresholds** — let the project configure minimum severity for blocking vs warning. `CRITICAL` always blocks. `LOW` advisory only. Configurable per invariant.
```
