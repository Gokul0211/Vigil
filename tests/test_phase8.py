import pytest
import json
from pathlib import Path
from datetime import datetime


# ---------- Fix 1: diff_preview + full diff ----------

def test_logger_writes_full_diff_for_long_diffs(tmp_path):
    from audit.logger import AuditLogger
    from models.context_entry import ContextEntry
    from models.intent import IntentMessage
    from models.verdict import Verdict

    logger = AuditLogger(session_id="p8t1", log_dir=str(tmp_path))
    intent = IntentMessage(intent="x", reason="y", affects=[], invariants_touched=[], assumes=[])
    long_diff = "x = " + "a" * 1000  # 1004 chars, over 600 threshold
    entry = ContextEntry(call_id=1, tool="vigil_create_file", file_path="src/x.py",
                         diff=long_diff, intent=intent, verdict="SKIP")
    logger.log_tool_call(entry)

    log_path = tmp_path / "session_p8t1.jsonl"
    events = [json.loads(l) for l in log_path.read_text().strip().splitlines() if l]
    tool_event = next(e for e in events if e["event"] == "tool_call")

    assert tool_event["diff_preview"] == long_diff[:600]
    assert tool_event["full_diff_path"] is not None
    assert Path(tool_event["full_diff_path"]).exists()
    full = Path(tool_event["full_diff_path"]).read_text()
    assert full == long_diff


def test_logger_no_full_diff_for_short_diffs(tmp_path):
    from audit.logger import AuditLogger
    from models.context_entry import ContextEntry
    from models.intent import IntentMessage

    logger = AuditLogger(session_id="p8t2", log_dir=str(tmp_path))
    intent = IntentMessage(intent="x", reason="y", affects=[], invariants_touched=[], assumes=[])
    entry = ContextEntry(call_id=1, tool="vigil_create_file", file_path="src/x.py",
                         diff="x = 1", intent=intent, verdict="SKIP")
    logger.log_tool_call(entry)

    log_path = tmp_path / "session_p8t2.jsonl"
    events = [json.loads(l) for l in log_path.read_text().strip().splitlines() if l]
    tool_event = next(e for e in events if e["event"] == "tool_call")
    assert tool_event["full_diff_path"] is None


# ---------- Fix 2: dataset negative samples ----------

def test_dataset_includes_negatives_when_flag_set(tmp_path):
    from audit.dataset import generate_dataset

    session_id = "negtest"
    log_path = tmp_path / f"session_{session_id}.jsonl"
    ts = datetime.utcnow().isoformat()

    events = [
        {"event": "session_start", "session_id": session_id, "timestamp": ts},
        {"event": "brief_generated", "session_id": session_id, "brief_preview": "Test.", "timestamp": ts},
        {"event": "tool_call", "call_id": 1, "tool": "vigil_create_file", "file": "a.py",
         "diff_preview": "x = 1", "full_diff_path": None,
         "intent": {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []},
         "verdict": "CLEAR_BLOCK", "severity": "HIGH", "finding": "hardcoded secret",
         "fix": "use env", "invariant_violated": "no-secrets", "vulnerability_class": "secret",
         "malformed_intent": False, "timestamp": ts},
        {"event": "tool_call", "call_id": 2, "tool": "vigil_create_file", "file": "b.py",
         "diff_preview": "y = 2", "full_diff_path": None,
         "intent": {"intent": "y", "reason": "z", "affects": [], "invariants_touched": [], "assumes": []},
         "verdict": "CLEAR_PASS", "malformed_intent": False, "timestamp": ts},
    ]
    with open(log_path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    out = str(tmp_path / "out.jsonl")
    generate_dataset(session_id, log_dir=str(tmp_path), out_path=out, include_negatives=True)

    with open(out) as f:
        records = [json.loads(l) for l in f if l.strip()]

    sample_types = [r["metadata"]["sample_type"] for r in records]
    assert "positive_high_confidence" in sample_types
    assert "negative" in sample_types


# ---------- Fix 3: semantic synonym expansion ----------

def test_semantic_expansion_finds_auth_synonym(tmp_path):
    from audit.verifier import _find_relevant_dirs, _expand_assumption_keywords
    (tmp_path / "middleware").mkdir()
    (tmp_path / "auth").mkdir()

    keywords = _expand_assumption_keywords("authentication handled upstream")
    assert "auth" in keywords or "middleware" in keywords

    dirs = _find_relevant_dirs("authentication handled upstream", str(tmp_path))
    dir_names = [d.name for d in dirs]
    assert "middleware" in dir_names or "auth" in dir_names


def test_semantic_expansion_rbac(tmp_path):
    from audit.verifier import _expand_assumption_keywords
    keywords = _expand_assumption_keywords("RBAC enforced externally")
    assert "role" in keywords


def test_semantic_expansion_unrecognized_falls_back(tmp_path):
    from audit.verifier import _expand_assumption_keywords
    # Should not raise even for completely unrecognized assumption
    keywords = _expand_assumption_keywords("the cosmic background radiation handles this")
    assert isinstance(keywords, list)


# ---------- Fix 4: infra scope distinction ----------

def test_infra_assumption_detected():
    from audit.verifier import _is_infra_assumption
    assert _is_infra_assumption("VPC enforces admin-only access")
    assert _is_infra_assumption("AWS API Gateway handles rate limiting")
    assert _is_infra_assumption("Kubernetes network policy restricts traffic")


def test_non_infra_assumption_not_detected():
    from audit.verifier import _is_infra_assumption
    assert not _is_infra_assumption("JWT middleware active on all routes")
    assert not _is_infra_assumption("rate limiting configured in middleware")


@pytest.mark.asyncio
async def test_infra_assumption_gets_infrastructure_scope(tmp_path):
    import json
    from datetime import datetime
    from audit.verifier import verify_assumptions

    session_id = "infratest"
    log_path = tmp_path / f"session_{session_id}.jsonl"
    ts = datetime.utcnow().isoformat()
    events = [
        {"event": "session_start", "session_id": session_id, "timestamp": ts},
        {"event": "tool_call", "call_id": 1, "tool": "vigil_create_file", "file": "src/x.py",
         "intent": {"intent": "x", "reason": "y", "affects": ["auth"], "invariants_touched": [],
                    "assumes": ["VPC enforces admin-only network access"]},
         "verdict": "AMBIGUOUS", "malformed_intent": False, "timestamp": ts}
    ]
    with open(log_path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    results = await verify_assumptions(session_id, project_root=str(tmp_path), log_dir=str(tmp_path))
    assert len(results) == 1
    assert results[0].scope == "INFRASTRUCTURE"
    assert results[0].status == "UNVERIFIED"
    assert "Infrastructure assumption" in results[0].evidence


# ---------- Fix 5: LLM evidence validation ----------

def test_vague_evidence_downgraded_to_inconclusive():
    from audit.verifier import _validate_llm_evidence
    status, confidence, evidence = _validate_llm_evidence(
        "VERIFIED", "The code handles authentication correctly."
    )
    assert status == "INCONCLUSIVE"
    assert confidence == "LOW"


def test_specific_evidence_kept_as_verified():
    from audit.verifier import _validate_llm_evidence
    status, confidence, evidence = _validate_llm_evidence(
        "VERIFIED", "verify_token() in middleware/auth.py calls jwt.decode() with the correct secret"
    )
    assert status == "VERIFIED"
    assert confidence == "HIGH"


def test_unverified_evidence_not_touched():
    from audit.verifier import _validate_llm_evidence
    status, confidence, evidence = _validate_llm_evidence(
        "UNVERIFIED", "No authentication middleware found in scanned directories."
    )
    assert status == "UNVERIFIED"


# ---------- Fix 6: brief quality validation ----------

def test_brief_validates_too_few_invariants():
    from brief.generator import validate_brief
    from brief.schema import ArchitectureBrief, TrustBoundary
    brief = ArchitectureBrief(
        system_purpose="A payment processing microservice for e-commerce.",
        trust_boundaries=[TrustBoundary(label="PUBLIC", patterns=["/api/*"])],
        auth_model="JWT middleware on all routes validates tokens.",
        data_flows=["User input -> DB"],
        invariants=[],  # empty
        sensitive_operations=["DB writes"],
        raw_markdown=""
    )
    issues = validate_brief(brief)
    assert any("invariant" in i.lower() for i in issues)


def test_brief_validates_vague_invariants():
    from brief.generator import validate_brief
    from brief.schema import ArchitectureBrief, SecurityInvariant, TrustBoundary
    brief = ArchitectureBrief(
        system_purpose="A payment processing microservice handling card data.",
        trust_boundaries=[TrustBoundary(label="PUBLIC", patterns=["/api/*"])],
        auth_model="JWT middleware on all /api/v1/ routes.",
        data_flows=["User input -> validation -> DB"],
        invariants=[
            SecurityInvariant(id="sec-1", description="handle security correctly"),
            SecurityInvariant(id="sec-2", description="follow best practices"),
        ],
        sensitive_operations=["DB writes"],
        raw_markdown=""
    )
    issues = validate_brief(brief)
    assert any("vague" in i.lower() or "falsifiable" in i.lower() for i in issues)


def test_brief_passes_validation_with_good_content():
    from brief.generator import validate_brief
    from brief.schema import ArchitectureBrief, SecurityInvariant, TrustBoundary
    brief = ArchitectureBrief(
        system_purpose="Payment microservice handling card transactions and user PII for e-commerce platform.",
        trust_boundaries=[
            TrustBoundary(label="PUBLIC", patterns=["/api/v1/checkout"]),
            TrustBoundary(label="INTERNAL ONLY", patterns=["/admin/*"])
        ],
        auth_model="JWT tokens validated by middleware on all /api/v1/ routes. Admin routes require role=admin claim.",
        data_flows=["User input -> validation -> DB write", "Payment data never logged"],
        invariants=[
            SecurityInvariant(id="no-pii-in-logs", description="Payment data must never appear in any log call"),
            SecurityInvariant(id="no-hardcoded-secrets", description="No API keys may be hardcoded in source"),
        ],
        sensitive_operations=["DB writes", "Payment API calls"],
        raw_markdown="# Architecture Brief\n..."
    )
    issues = validate_brief(brief)
    assert issues == []
