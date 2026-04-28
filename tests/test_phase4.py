import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from models.verdict import Verdict
from models.intent import IntentMessage

def make_intent(**kwargs):
    defaults = {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []}
    defaults.update(kwargs)
    return IntentMessage(**defaults)


# ---------- Tier 2 verdict parsing ----------

from server.tier2 import _parse_verdict

def test_tier2_parse_block():
    raw = '{"verdict": "BLOCK", "severity": "HIGH", "vulnerability_class": "business-logic/auth-bypass", "finding": "auth skipped on internal route", "fix": "add auth check", "invariant_violated": "admin-role-required"}'
    v = _parse_verdict(raw)
    assert v.verdict == "BLOCK"
    assert v.vulnerability_class == "business-logic/auth-bypass"
    assert v.invariant_violated == "admin-role-required"

def test_tier2_parse_approve():
    raw = '{"verdict": "APPROVE", "severity": null, "vulnerability_class": null, "finding": "rate limiting correctly applied", "fix": null, "invariant_violated": null}'
    v = _parse_verdict(raw)
    assert v.verdict == "APPROVE"

def test_tier2_parse_failure_defaults_to_approve():
    raw = "not valid json"
    v = _parse_verdict(raw)
    assert v.verdict == "APPROVE"  # Tier 2 failures must never block


# ---------- pending_block injection ----------

@pytest.mark.asyncio
async def test_pending_block_injected_at_next_call(tmp_path, monkeypatch):
    """
    Scenario:
      Call #1: AMBIGUOUS → Tier 2 runs async, finds BLOCK
      Call #2: pending_block is injected BEFORE call #2 proceeds
    """
    from brief.generator import _parse_brief
    from server.interceptor import Interceptor
    from server.context import ContextManager
    from audit.logger import AuditLogger

    BRIEF_MD = """# Architecture Brief
## System Purpose
Test.
## Trust Boundaries
- PUBLIC: /api/*
## Auth Model
JWT.
## Data Flows
- User -> DB
## Security Invariants
- [ ] no-unverified-auth: Auth assumptions must be verified
## Sensitive Operations
- Auth checks
"""
    brief = _parse_brief(BRIEF_MD)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="t2test", log_dir=str(tmp_path))
    interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="t2test")

    # Mock Tier 1 to return AMBIGUOUS
    monkeypatch.setattr(
        "server.interceptor.analyze_sync",
        lambda **kwargs: Verdict(verdict="AMBIGUOUS")
    )

    # Mock Tier 2 to return BLOCK (runs async)
    block_verdict = Verdict(
        verdict="BLOCK", severity="HIGH",
        finding="VPC assumption unverified",
        fix="Add network policy config",
        invariant_violated="no-unverified-auth"
    )
    async def mock_tier2(**kwargs):
        return block_verdict
    monkeypatch.setattr("server.interceptor.analyze_async", mock_tier2)

    # Call #1 — AMBIGUOUS, file written, Tier 2 task spawned
    f1 = tmp_path / "file1.py"
    result1 = await interceptor.handle(
        tool="vigil_create_file", file_path=str(f1),
        params={"path": str(f1), "file_text": "x = 1"},
        intent_raw={**make_intent(affects=["auth"], assumes=["VPC enforces this"]).model_dump()}
    )
    assert "AMBIGUOUS" in result1
    assert f1.exists()  # file was written

    # Let the background task complete
    await asyncio.sleep(0.1)

    # Call #2 — pending_block should be injected, call halted
    f2 = tmp_path / "file2.py"
    result2 = await interceptor.handle(
        tool="vigil_create_file", file_path=str(f2),
        params={"path": str(f2), "file_text": "y = 2"},
        intent_raw={**make_intent().model_dump()}
    )
    assert "DEFERRED BLOCK" in result2
    assert "VPC assumption unverified" in result2
    assert not f2.exists()  # second file must NOT have been written


# ---------- Context compression ----------

def test_compression_triggered_at_100(monkeypatch):
    from brief.generator import _parse_brief
    from server.context import ContextManager
    from models.context_entry import ContextEntry

    BRIEF_MD = """# Architecture Brief
## System Purpose
Test.
## Trust Boundaries
- PUBLIC: /api/*
## Auth Model
JWT.
## Data Flows
- User -> DB
## Security Invariants
## Sensitive Operations
"""
    brief = _parse_brief(BRIEF_MD)
    ctx = ContextManager(brief=brief)

    # Mock the compression API call
    monkeypatch.setattr(
        "server.context._client.messages.create",
        lambda **kwargs: type("R", (), {"content": [type("C", (), {"text": "compressed summary"})()]})()
    )

    intent = make_intent()
    for i in range(105):
        entry = ContextEntry(
            call_id=i+1, tool="vigil_create_file",
            file_path=f"file{i}.py", diff="x = 1",
            intent=intent, verdict="SKIP"
        )
        ctx.append(entry)

    # After compression, entries should be fewer than 105
    assert len(ctx.entries) < 105
    # Summary should be set
    assert ctx._compressed_summary != ""

def test_block_entries_never_compressed(monkeypatch):
    """BLOCK entries must survive compression."""
    from brief.generator import _parse_brief
    from server.context import ContextManager
    from models.context_entry import ContextEntry
    from models.verdict import Verdict

    BRIEF_MD = """# Architecture Brief
## System Purpose
Test.
## Trust Boundaries
- PUBLIC: /api/*
## Auth Model
JWT.
## Data Flows
- User -> DB
## Security Invariants
## Sensitive Operations
"""
    brief = _parse_brief(BRIEF_MD)
    ctx = ContextManager(brief=brief)

    monkeypatch.setattr(
        "server.context._client.messages.create",
        lambda **kwargs: type("R", (), {"content": [type("C", (), {"text": "summary"})()]})()
    )

    intent = make_intent()
    for i in range(99):
        entry = ContextEntry(
            call_id=i+1, tool="vigil_create_file",
            file_path=f"file{i}.py", diff="x = 1",
            intent=intent, verdict="SKIP"
        )
        ctx.append(entry)

    # Insert a BLOCK entry
    block_entry = ContextEntry(
        call_id=100, tool="vigil_create_file",
        file_path="critical.py", diff="eval(user_input)",
        intent=intent, verdict="CLEAR_BLOCK",
        full_verdict=Verdict(verdict="CLEAR_BLOCK", severity="CRITICAL", finding="eval injection")
    )
    ctx.append(block_entry)  # this triggers compression

    block_ids = [e.call_id for e in ctx.entries if e.verdict in ("BLOCK", "CLEAR_BLOCK")]
    assert 100 in block_ids  # BLOCK entry preserved
