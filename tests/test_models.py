import json
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
        assumes=[],
    )
    assert "auth" in msg.affects
    assert not msg.is_empty
    assert not msg.is_malformed


def test_intent_normalizes_affects():
    msg = IntentMessage(
        intent="x", reason="y", affects=["AUTH", " Crypto "], invariants_touched=[], assumes=[]
    )
    assert "auth" in msg.affects
    assert "crypto" in msg.affects


def test_intent_empty_detection():
    msg = IntentMessage(intent="", reason="", affects=[], invariants_touched=[], assumes=[])
    assert msg.is_empty


def test_intent_malformed_detection():
    msg = IntentMessage(
        intent="x", reason="y", affects=["garbage_domain"], invariants_touched=[], assumes=[]
    )
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
    with open("tests/fixtures/sample_brief.json") as f:
        data = json.load(f)
    brief = ArchitectureBrief(**data)
    assert len(brief.invariants) == 4
    assert brief.invariants[0].id == "no-pii-in-logs"


def test_context_entry_timestamps():
    intent = IntentMessage(intent="x", reason="y", affects=[], invariants_touched=[], assumes=[])
    entry = ContextEntry(
        call_id=1,
        tool="vigil_create_file",
        file_path="src/x.py",
        diff="print('hello')",
        intent=intent,
        verdict="SKIP",
    )
    assert entry.timestamp is not None
