# Vigil — Phase 1: Project Scaffold & Data Models

## What This Phase Builds

The foundation everything else depends on. No model calls, no interception logic, no MCP server yet. Just the project skeleton, all Pydantic schemas, and a verified import graph. When this phase is done, every subsequent phase has a clean, typed foundation to build on.

---

## Project Structure to Create

```
vigil/
├── server/
│   ├── __init__.py
│   ├── main.py              # empty stub — filled in Phase 2
│   ├── interceptor.py       # empty stub — filled in Phase 2
│   ├── classifier.py        # empty stub — filled in Phase 3
│   ├── tier1.py             # empty stub — filled in Phase 3
│   ├── tier2.py             # empty stub — filled in Phase 4
│   └── context.py           # empty stub — filled in Phase 4
├── brief/
│   ├── __init__.py
│   ├── generator.py         # empty stub — filled in Phase 2
│   └── schema.py            # IMPLEMENT in this phase
├── models/
│   ├── __init__.py
│   ├── intent.py            # IMPLEMENT in this phase
│   ├── verdict.py           # IMPLEMENT in this phase
│   └── context_entry.py     # IMPLEMENT in this phase
├── audit/
│   ├── __init__.py
│   └── logger.py            # IMPLEMENT in this phase
├── prompts/
│   ├── brief_generation.txt # IMPLEMENT in this phase
│   ├── tier1.txt            # IMPLEMENT in this phase
│   └── tier2.txt            # IMPLEMENT in this phase
├── tests/
│   ├── __init__.py
│   ├── test_models.py       # IMPLEMENT in this phase
│   └── fixtures/
│       ├── sample_intent_valid.json
│       ├── sample_intent_malformed.json
│       └── sample_brief.json
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Dependencies

`pyproject.toml` / `requirements.txt` must include:

```
pydantic>=2.0
anthropic>=0.25.0
mcp>=1.0.0          # MCP Python SDK
pytest
pytest-asyncio
python-dotenv
```

Use Python 3.11+. All async code uses `asyncio`. No other frameworks.

---

## Models to Implement

### `models/intent.py` — IntentMessage

This is parsed directly from the tool call parameters. All fields are required. The agent cannot omit them because they are parameters in the MCP tool signature (enforced in Phase 2). However, fields can be empty lists or empty strings — the classifier handles that in Phase 3.

```python
from pydantic import BaseModel, field_validator
from typing import Literal

VALID_AFFECTS_DOMAINS = {
    "auth", "crypto", "logging", "data-exposure",
    "input-validation", "file-system", "network", "none", "unknown"
}

class IntentMessage(BaseModel):
    intent: str                       # one-line description of what this code block does
    reason: str                       # why this decision was made
    affects: list[str]                # security domains touched — validated against VALID_AFFECTS_DOMAINS
    invariants_touched: list[str]     # invariant IDs from the brief being intentionally relaxed
    assumes: list[str]                # external guarantees being relied on

    @field_validator("affects", mode="before")
    @classmethod
    def normalize_affects(cls, v):
        # lowercase, strip whitespace, deduplicate
        return list({a.strip().lower() for a in v}) if v else []

    @property
    def is_empty(self) -> bool:
        """True if the agent passed no meaningful INTENT data."""
        return (
            not self.intent.strip()
            and not self.affects
            and not self.invariants_touched
            and not self.assumes
        )

    @property
    def is_malformed(self) -> bool:
        """True if affects contains values outside the valid domain set."""
        return bool(self.affects) and not any(
            a in VALID_AFFECTS_DOMAINS for a in self.affects
        )
```

### `models/verdict.py` — Verdict + ToolCallResult

Two classes here. `Verdict` is what Tier 1 and Tier 2 return. `ToolCallResult` is what `handle_tool_call` returns to the coding agent.

```python
from pydantic import BaseModel
from typing import Literal

VerdictType = Literal["CLEAR_BLOCK", "CLEAR_PASS", "AMBIGUOUS", "APPROVE", "BLOCK", "SKIP"]
SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None

class Verdict(BaseModel):
    verdict: VerdictType
    severity: SeverityLevel = None
    vulnerability_class: str | None = None   # e.g. "business-logic/auth-bypass"
    finding: str | None = None               # human-readable explanation
    fix: str | None = None                   # suggested fix
    invariant_violated: str | None = None    # invariant ID from brief, if any
    detected_at: int | None = None           # call_id when finding was generated (Tier 2)
    injected_at: int | None = None           # call_id when finding was injected (Tier 2)

class ToolCallResult(BaseModel):
    """
    Returned to the coding agent after handle_tool_call.
    If blocked=True, the agent must address finding before proceeding.
    If deferred=True, a prior Tier 2 finding is being injected now.
    """
    allowed: bool
    blocked: bool = False
    deferred: bool = False                   # True when injecting a pending Tier 2 block
    verdict: Verdict | None = None
    message: str = ""                        # human-readable message to return to agent
```

### `models/context_entry.py` — ContextEntry

One entry is appended to the session context after every tool call that reaches the classifier. SKIP'd calls are also recorded (with verdict="SKIP") so the audit log is complete.

```python
from pydantic import BaseModel
from datetime import datetime
from .intent import IntentMessage
from .verdict import Verdict, VerdictType

class ContextEntry(BaseModel):
    call_id: int
    tool: str                          # "vigil_write_file" | "vigil_str_replace" | "vigil_create_file"
    file_path: str
    diff: str                          # extracted diff text
    intent: IntentMessage
    verdict: VerdictType
    full_verdict: Verdict | None = None
    timestamp: datetime = None
    malformed_intent: bool = False     # True if intent fields were empty/garbage, diff inference was used

    def model_post_init(self, __context):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
```

### `brief/schema.py` — ArchitectureBrief + SecurityInvariant

```python
from pydantic import BaseModel

class SecurityInvariant(BaseModel):
    id: str              # short slug, e.g. "no-pii-in-logs", "admin-role-required"
    description: str     # human-readable, e.g. "Payment data must never appear in log calls"
    satisfied: bool = True  # flipped to False when a BLOCK references this invariant

class TrustBoundary(BaseModel):
    label: str           # "PUBLIC" | "AUTHENTICATED" | "INTERNAL ONLY"
    patterns: list[str]  # route patterns, e.g. ["/api/v1/checkout", "/api/v1/products"]

class ArchitectureBrief(BaseModel):
    system_purpose: str
    trust_boundaries: list[TrustBoundary]
    auth_model: str
    data_flows: list[str]
    invariants: list[SecurityInvariant]
    sensitive_operations: list[str]
    raw_markdown: str = ""   # the full markdown brief as generated by Phase 1 reasoning model
```

---

## Audit Logger — `audit/logger.py`

Writes a structured JSONL audit log. One line per tool call. The file is created at session start and appended on every call.

```python
import json
from pathlib import Path
from datetime import datetime
from models.context_entry import ContextEntry

class AuditLogger:
    def __init__(self, session_id: str, log_dir: str = "logs"):
        self.session_id = session_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"session_{session_id}.jsonl"
        self._write_session_start()

    def _write_session_start(self):
        entry = {
            "event": "session_start",
            "session_id": self.session_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        self._append(entry)

    def log_tool_call(self, entry: ContextEntry):
        record = {
            "event": "tool_call",
            "call_id": entry.call_id,
            "tool": entry.tool,
            "file": entry.file_path,
            "intent": entry.intent.model_dump(),
            "verdict": entry.verdict,
            "malformed_intent": entry.malformed_intent,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        }
        if entry.full_verdict:
            record["severity"] = entry.full_verdict.severity
            record["finding"] = entry.full_verdict.finding
            record["fix"] = entry.full_verdict.fix
            record["invariant_violated"] = entry.full_verdict.invariant_violated
        self._append(record)

    def log_brief_generated(self, brief_markdown: str):
        self._append({
            "event": "brief_generated",
            "session_id": self.session_id,
            "brief_preview": brief_markdown[:500],
            "timestamp": datetime.utcnow().isoformat()
        })

    def log_malformed_intent(self, call_id: int, tool: str, file_path: str, reason: str):
        self._append({
            "event": "malformed_intent",
            "call_id": call_id,
            "tool": tool,
            "file": file_path,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        })

    def _append(self, record: dict):
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
```

---

## Prompt Files

Create these as plain text files under `prompts/`. They are loaded at runtime, not hardcoded in Python.

### `prompts/brief_generation.txt`

```
You are a security architecture analyst. You will be given a description of a software system to be built.

Your job is to produce a structured Architecture Brief that will be used as the ground truth for a real-time security watcher during the coding session.

The brief must define:
1. System Purpose — one paragraph describing what the system does
2. Trust Boundaries — classify all endpoints or subsystems as PUBLIC, AUTHENTICATED, or INTERNAL ONLY
3. Auth Model — describe how authentication and authorization work
4. Data Flows — describe how sensitive data moves through the system
5. Security Invariants — list specific conditions that must ALWAYS hold, as checkable assertions. Assign each a short ID slug (e.g. "no-pii-in-logs").
6. Sensitive Operations — list operations that touch auth, crypto, PII, external APIs, file system, or environment variables

Be specific. Vague invariants ("handle auth correctly") are useless. Good invariants are falsifiable ("Payment data must never appear in any log call").

Output ONLY a markdown document following this structure exactly:

# Architecture Brief

## System Purpose
<paragraph>

## Trust Boundaries
- <LABEL>: <pattern1>, <pattern2>

## Auth Model
<description>

## Data Flows
- <flow description>

## Security Invariants
- [ ] <id>: <description>

## Sensitive Operations
- <operation>
```

### `prompts/tier1.txt`

```
You are a fast security classifier. You will receive a code diff and a structured INTENT message.

Your ONLY job is to decide quickly with HIGH confidence. Do not speculate. Do not guess.

Flag ONLY things you are certain about:
- Hardcoded secrets, API keys, or passwords directly in code
- Unsanitized user input used directly in a DB query, shell command, or eval()
- PII or payment data written to a log or print statement
- The INTENT claims something that the diff clearly does not do (intent-code mismatch)

If you are even slightly unsure about anything, return AMBIGUOUS. AMBIGUOUS is the right answer when you see something that might be a problem but requires more context to confirm.

Never return CLEAR_BLOCK based on speculation. Never return CLEAR_PASS if you see anything suspicious. When in doubt: AMBIGUOUS.

You will be given:
- ARCHITECTURE BRIEF: the security ground truth for this session
- INTENT: the structured intent parameters the agent provided
- DIFF: the code content being written

Respond ONLY in valid JSON, no markdown, no explanation outside the JSON:
{
  "verdict": "CLEAR_BLOCK" | "CLEAR_PASS" | "AMBIGUOUS",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null,
  "finding": "<concise explanation of what was flagged, or null>",
  "fix": "<specific fix suggestion, or null>",
  "invariant_violated": "<invariant ID from brief, or null>"
}
```

### `prompts/tier2.txt`

```
You are a deep security reasoning agent embedded in a live coding session.

You have been given:
1. An Architecture Brief — the security ground truth for this session (trust boundaries, auth model, data flows, invariants)
2. The full accumulated session history — every prior code diff with its INTENT and the verdict it received
3. The current code diff and its INTENT parameters — flagged AMBIGUOUS by the fast classifier

Your job is to reason carefully about things that require cross-context understanding:
- Business logic flaws: does this code, combined with what was written earlier, create a vulnerability?
- Architectural drift: does this code deviate from the brief in a way that creates a security gap?
- Unverified ASSUMES: the agent claims an external guarantee (e.g. "VPC enforces this"). Look through the session history — has any code been written that actually implements that guarantee? If not, the assumption is unverified.
- Intent-code mismatch: the agent says X, but the diff does Y. Flag the gap.

Be specific in your findings. Reference call IDs from the session history. Reference invariant IDs from the brief. Tell the agent exactly what to fix.

If you see no issue, return APPROVE with brief notes.

Respond ONLY in valid JSON, no markdown, no explanation outside the JSON:
{
  "verdict": "APPROVE" | "BLOCK",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null,
  "vulnerability_class": "<e.g. business-logic/auth-bypass, or null>",
  "finding": "<detailed explanation — reference call IDs and invariant IDs>",
  "fix": "<specific, actionable fix suggestion>",
  "invariant_violated": "<invariant ID from brief, or null>"
}
```

---

## Test Fixtures to Create

### `tests/fixtures/sample_intent_valid.json`
```json
{
  "intent": "implementing checkout route with JWT auth check",
  "reason": "core payment flow, auth required per brief",
  "affects": ["auth", "data-exposure"],
  "invariants_touched": [],
  "assumes": ["JWT middleware active on /api/v1/ routes"]
}
```

### `tests/fixtures/sample_intent_malformed.json`
```json
{
  "intent": "",
  "reason": "",
  "affects": [],
  "invariants_touched": [],
  "assumes": []
}
```

### `tests/fixtures/sample_brief.json`
```json
{
  "system_purpose": "Payment processing microservice for e-commerce platform.",
  "trust_boundaries": [
    {"label": "PUBLIC", "patterns": ["/api/v1/checkout", "/api/v1/products"]},
    {"label": "AUTHENTICATED", "patterns": ["/api/v1/orders", "/api/v1/user/*"]},
    {"label": "INTERNAL ONLY", "patterns": ["/api/internal/*", "/admin/*"]}
  ],
  "auth_model": "JWT-based. Middleware validates token on all /api/v1/ routes. /api/internal/ assumed to be behind VPC.",
  "data_flows": [
    "User input -> validation -> DB write (orders table)",
    "Payment data -> never logged, never stored raw",
    "PII fields: email, address, card_last4"
  ],
  "invariants": [
    {"id": "no-pii-in-logs", "description": "Payment data must never appear in any log call", "satisfied": true},
    {"id": "admin-role-required", "description": "/admin/* never reachable without role=admin claim", "satisfied": true},
    {"id": "db-writes-sanitized", "description": "All DB writes sanitized before execution", "satisfied": true},
    {"id": "rate-limit-public", "description": "Rate limiting on all public endpoints", "satisfied": true}
  ],
  "sensitive_operations": ["DB writes", "External payment API calls", "File system access", "Environment variable reads"],
  "raw_markdown": ""
}
```

---

## Tests to Write — `tests/test_models.py`

Cover every schema. These are the ground-truth contracts for every other phase.

```python
import pytest
from models.intent import IntentMessage
from models.verdict import Verdict, ToolCallResult
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief, SecurityInvariant

def test_intent_valid():
    msg = IntentMessage(
        intent="add checkout route",
        reason="core flow",
        affects=["auth", "data-exposure"],
        invariants_touched=[],
        assumes=[]
    )
    assert "auth" in msg.affects
    assert not msg.is_empty
    assert not msg.is_malformed

def test_intent_normalizes_affects():
    msg = IntentMessage(intent="x", reason="y", affects=["AUTH", " Crypto "], invariants_touched=[], assumes=[])
    assert "auth" in msg.affects
    assert "crypto" in msg.affects

def test_intent_empty_detection():
    msg = IntentMessage(intent="", reason="", affects=[], invariants_touched=[], assumes=[])
    assert msg.is_empty

def test_intent_malformed_detection():
    msg = IntentMessage(intent="x", reason="y", affects=["garbage_domain"], invariants_touched=[], assumes=[])
    assert msg.is_malformed

def test_verdict_block():
    v = Verdict(verdict="CLEAR_BLOCK", severity="HIGH", finding="hardcoded API key", fix="use env var")
    assert v.verdict == "CLEAR_BLOCK"
    assert v.severity == "HIGH"

def test_verdict_approve():
    v = Verdict(verdict="APPROVE")
    assert v.finding is None

def test_tool_call_result_blocked():
    v = Verdict(verdict="CLEAR_BLOCK", severity="CRITICAL", finding="SQL injection")
    r = ToolCallResult(allowed=False, blocked=True, verdict=v, message="Blocked: SQL injection detected")
    assert not r.allowed
    assert r.blocked

def test_brief_loads_from_fixture():
    import json
    with open("tests/fixtures/sample_brief.json") as f:
        data = json.load(f)
    brief = ArchitectureBrief(**data)
    assert len(brief.invariants) == 4
    assert brief.invariants[0].id == "no-pii-in-logs"

def test_context_entry_timestamps():
    from models.intent import IntentMessage
    intent = IntentMessage(intent="x", reason="y", affects=[], invariants_touched=[], assumes=[])
    entry = ContextEntry(call_id=1, tool="vigil_create_file", file_path="src/x.py", diff="print('hello')", intent=intent, verdict="SKIP")
    assert entry.timestamp is not None
```

---

## Completion Criteria for Phase 1

Before moving to Phase 2, verify:

- [ ] `pytest tests/test_models.py` passes with no errors
- [ ] All schemas import cleanly: `from models.intent import IntentMessage` etc.
- [ ] All stub files exist and are importable (even if empty)
- [ ] All three prompt files exist under `prompts/` and are non-empty
- [ ] All three fixture JSON files exist under `tests/fixtures/`
- [ ] `AuditLogger` can be instantiated and writes a valid JSONL file
- [ ] No circular imports anywhere in the module tree

## What Phase 2 Will Build On

Phase 2 takes these schemas and builds:
- The MCP server entrypoint (`server/main.py`)
- The three `vigil_*` tool definitions with INTENT parameters
- The Architecture Brief generator (`brief/generator.py`)
- Session initialization flow (brief generation → session start → logger init)
