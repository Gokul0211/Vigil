import pytest
import json
import os
from unittest.mock import patch
from models.verdict import Verdict
from models.intent import IntentMessage
from brief.schema import ArchitectureBrief, SecurityInvariant, TrustBoundary


BRIEF_MD = """# Architecture Brief
## System Purpose
Payment service.
## Trust Boundaries
- PUBLIC: /api/v1/*
- INTERNAL ONLY: /admin/*
## Auth Model
JWT.
## Data Flows
- User -> DB
## Security Invariants
- [ ] no-hardcoded-secrets: No secrets hardcoded in source
- [ ] no-pii-in-logs: Payment data must never appear in logs
## Sensitive Operations
- DB writes
"""


def make_intent(**kwargs):
    defaults = {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []}
    defaults.update(kwargs)
    return IntentMessage(**defaults)


async def make_interceptor(tmp_path, brief_md=None):
    from brief.generator import _parse_brief
    from server.interceptor import Interceptor
    from server.context import ContextManager
    from audit.logger import AuditLogger
    brief = _parse_brief(brief_md or BRIEF_MD)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="p6test", log_dir=str(tmp_path))
    return Interceptor(brief=brief, context=ctx, logger=logger, session_id="p6test")


# ---------- Part 1: Invariant validation ----------

def test_validate_invariant_clears_hallucinated_id():
    from server.tier1 import _validate_invariant
    from brief.generator import _parse_brief
    brief = _parse_brief(BRIEF_MD)
    verdict = Verdict(verdict="CLEAR_BLOCK", severity="HIGH",
                      finding="SQL injection", invariant_violated="nonexistent-invariant")
    result = _validate_invariant(verdict, brief)
    assert result.invariant_violated is None


def test_validate_invariant_keeps_valid_id():
    from server.tier1 import _validate_invariant
    from brief.generator import _parse_brief
    brief = _parse_brief(BRIEF_MD)
    verdict = Verdict(verdict="CLEAR_BLOCK", severity="HIGH",
                      finding="PII in log", invariant_violated="no-pii-in-logs")
    result = _validate_invariant(verdict, brief)
    assert result.invariant_violated == "no-pii-in-logs"


def test_validate_invariant_null_passthrough():
    from server.tier1 import _validate_invariant
    from brief.generator import _parse_brief
    brief = _parse_brief(BRIEF_MD)
    verdict = Verdict(verdict="CLEAR_BLOCK", severity="HIGH",
                      finding="SQL injection", invariant_violated=None)
    result = _validate_invariant(verdict, brief)
    assert result.invariant_violated is None


# ---------- Part 2: Severity thresholds ----------

@pytest.mark.asyncio
async def test_low_severity_below_threshold_becomes_warn(tmp_path, monkeypatch):
    """LOW finding when threshold is HIGH → WARN, file written."""
    monkeypatch.setenv("VIGIL_MIN_BLOCK_SEVERITY", "HIGH")
    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="CLEAR_BLOCK", severity="LOW",
                              finding="Minor issue", fix="Small fix")
    )

    target = tmp_path / "file.py"
    result = await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": "x = 1"},
        intent_raw=make_intent(affects=["auth"]).model_dump()
    )

    assert "WARN" in result
    assert target.exists()  # file written despite finding


@pytest.mark.asyncio
async def test_high_severity_at_threshold_still_blocks(tmp_path, monkeypatch):
    """HIGH finding when threshold is HIGH → still BLOCK."""
    monkeypatch.setenv("VIGIL_MIN_BLOCK_SEVERITY", "HIGH")
    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="CLEAR_BLOCK", severity="HIGH",
                              finding="Serious issue", fix="Fix it")
    )

    target = tmp_path / "file.py"
    result = await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": "x = 1"},
        intent_raw=make_intent(affects=["auth"]).model_dump()
    )

    assert "BLOCK" in result
    assert not target.exists()  # file NOT written


@pytest.mark.asyncio
async def test_default_threshold_blocks_everything(tmp_path, monkeypatch):
    """Default threshold (LOW) → even LOW severity blocks."""
    monkeypatch.delenv("VIGIL_MIN_BLOCK_SEVERITY", raising=False)
    interceptor = await make_interceptor(tmp_path)

    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kw: Verdict(verdict="CLEAR_BLOCK", severity="LOW",
                              finding="Minor issue", fix="Fix it")
    )

    target = tmp_path / "file.py"
    result = await interceptor.handle(
        tool="vigil_create_file", file_path=str(target),
        params={"path": str(target), "file_text": "x = 1"},
        intent_raw=make_intent(affects=["auth"]).model_dump()
    )

    assert "BLOCK" in result
    assert not target.exists()


# ---------- Part 3: Dataset generation ----------

def test_dataset_export_pairs_ambiguous_with_tier2(tmp_path):
    from audit.dataset import generate_dataset
    from datetime import datetime

    session_id = "dstest"
    log_path = tmp_path / f"session_{session_id}.jsonl"

    events = [
        {"event": "session_start", "session_id": session_id, "timestamp": datetime.utcnow().isoformat()},
        {"event": "brief_generated", "session_id": session_id, "brief_preview": "Payment service.", "timestamp": datetime.utcnow().isoformat()},
        {
            "event": "tool_call", "call_id": 1, "tool": "vigil_create_file",
            "file": "src/db.py", "diff_preview": "db.execute(f'SELECT * FROM users WHERE id = {uid}')",
            "intent": {"intent": "fetch user", "reason": "profile", "affects": ["input-validation"], "invariants_touched": [], "assumes": []},
            "verdict": "AMBIGUOUS", "malformed_intent": False, "timestamp": datetime.utcnow().isoformat()
        },
        {
            "event": "tool_call", "call_id": 1, "tool": "tier2_async_result",
            "file": "[async]", "diff_preview": "",
            "intent": {"intent": "fetch user", "reason": "profile", "affects": [], "invariants_touched": [], "assumes": []},
            "verdict": "BLOCK", "severity": "CRITICAL",
            "vulnerability_class": "injection/sql",
            "finding": "SQL injection in get_user",
            "fix": "Use parameterized query",
            "invariant_violated": None,
            "malformed_intent": False, "timestamp": datetime.utcnow().isoformat()
        }
    ]

    with open(log_path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    out_path = str(tmp_path / "dataset.jsonl")
    result = generate_dataset(session_id, log_dir=str(tmp_path), out_path=out_path)

    assert result == out_path
    with open(out_path) as f:
        records = [json.loads(l) for l in f if l.strip()]

    assert len(records) == 1
    r = records[0]
    assert r["input"]["intent"]["intent"] == "fetch user"
    assert r["output"]["verdict"] == "BLOCK"
    assert set(r["metadata"]["tags"]) == {"injection", "sql", "critical"}
    assert r["metadata"]["call_id"] == 1


def test_dataset_export_skips_unresolved_ambiguous(tmp_path):
    """AMBIGUOUS calls with no matching Tier 2 result are skipped."""
    from audit.dataset import generate_dataset
    from datetime import datetime

    session_id = "dstest2"
    log_path = tmp_path / f"session_{session_id}.jsonl"

    events = [
        {"event": "session_start", "session_id": session_id, "timestamp": datetime.utcnow().isoformat()},
        {
            "event": "tool_call", "call_id": 2, "tool": "vigil_create_file",
            "file": "src/x.py", "diff_preview": "x = 1",
            "intent": {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []},
            "verdict": "AMBIGUOUS", "malformed_intent": False, "timestamp": datetime.utcnow().isoformat()
        }
        # No matching tier2_async_result for call_id 2
    ]

    with open(log_path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    result = generate_dataset(session_id, log_dir=str(tmp_path))
    assert "No records" in result or "No AMBIGUOUS" in result


def test_dataset_export_not_found(tmp_path):
    from audit.dataset import generate_dataset
    with pytest.raises(FileNotFoundError):
        generate_dataset("nonexistent", log_dir=str(tmp_path))


def test_infer_tags():
    from audit.dataset import _infer_tags
    event = {
        "vulnerability_class": "injection/sql",
        "invariant_violated": "no-pii-in-logs",
        "severity": "CRITICAL"
    }
    tags = _infer_tags(event)
    assert "critical" in tags
    assert "no-pii-in-logs" in tags
    assert "injection" in tags or "sql" in tags
