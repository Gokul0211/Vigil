import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock
from brief.schema import ArchitectureBrief
from brief.generator import _parse_brief
from server.context import ContextManager
from server.interceptor import Interceptor
from audit.logger import AuditLogger
from models.intent import IntentMessage

SAMPLE_BRIEF_MARKDOWN = """
# Architecture Brief

## System Purpose
Payment processing microservice.

## Trust Boundaries
- PUBLIC: /api/v1/checkout, /api/v1/products
- AUTHENTICATED: /api/v1/orders
- INTERNAL ONLY: /api/internal/*, /admin/*

## Auth Model
JWT-based. Middleware on /api/v1/ routes.

## Data Flows
- User input -> validation -> DB write
- Payment data -> never logged

## Security Invariants
- [ ] no-pii-in-logs: Payment data must never appear in log calls
- [ ] admin-role-required: /admin/* never reachable without role=admin

## Sensitive Operations
- DB writes
- External payment API calls
"""

def test_parse_brief_sections():
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    assert "Payment" in brief.system_purpose
    assert len(brief.trust_boundaries) == 3
    assert len(brief.invariants) == 2
    assert brief.invariants[0].id == "no-pii-in-logs"

def test_parse_brief_trust_boundaries():
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    public = next(b for b in brief.trust_boundaries if b.label == "PUBLIC")
    assert "/api/v1/checkout" in public.patterns

def test_context_manager_call_ids():
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    ctx = ContextManager(brief=brief)
    assert ctx.next_call_id() == 1
    assert ctx.next_call_id() == 2
    assert len(ctx) == 0  # entries only added on append

@pytest.mark.asyncio
async def test_interceptor_stub_approves(tmp_path):
    from unittest.mock import patch
    from models.verdict import Verdict as V
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="test01", log_dir=str(tmp_path))
    interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="test01")

    with patch("server.interceptor.analyze_sync",
               return_value=V(verdict="CLEAR_PASS")):
        result = await interceptor.handle(
            tool="vigil_create_file",
            file_path=str(tmp_path / "test.py"),
            params={"path": str(tmp_path / "test.py"), "file_text": "print('hello')"},
            intent_raw={
                "intent": "create hello script",
                "reason": "testing",
                "affects": [],
                "invariants_touched": [],
                "assumes": []
            }
        )
    assert "APPROVE" in result
    assert len(ctx) == 1

@pytest.mark.asyncio
async def test_interceptor_creates_file(tmp_path):
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="test02", log_dir=str(tmp_path))
    interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="test02")

    target = tmp_path / "output.py"
    await interceptor.handle(
        tool="vigil_create_file",
        file_path=str(target),
        params={"path": str(target), "file_text": "x = 1"},
        intent_raw={"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []}
    )
    assert target.exists()
    assert target.read_text() == "x = 1"

def test_audit_log_written(tmp_path):
    logger = AuditLogger(session_id="test03", log_dir=str(tmp_path))
    log_file = tmp_path / "session_test03.jsonl"
    assert log_file.exists()
    lines = log_file.read_text().strip().splitlines()
    assert len(lines) == 1  # session_start event
    event = json.loads(lines[0])
    assert event["event"] == "session_start"
