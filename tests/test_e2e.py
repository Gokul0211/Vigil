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
        intent_raw=make_intent(affects=["input-validation"]).model_dump()
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

    await asyncio.sleep(0.15)

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
