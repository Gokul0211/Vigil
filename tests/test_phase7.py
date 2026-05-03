import pytest
import json
import os
from pathlib import Path
from datetime import datetime
from audit.verifier import (
    extract_assumptions,
    _find_relevant_dirs,
    _scan_directory,
    _extract_search_terms,
    _check_implementation_patterns,
    format_verification_report,
    AssumptionResult
)


def write_log(tmp_path, session_id, assumes_list):
    """Helper to write a minimal session log with assumptions."""
    log_path = tmp_path / f"session_{session_id}.jsonl"
    events = [
        {"event": "session_start", "session_id": session_id, "timestamp": datetime.utcnow().isoformat()},
        {
            "event": "tool_call", "call_id": 1,
            "tool": "vigil_create_file", "file": "src/routes/internal.py",
            "intent": {
                "intent": "add internal endpoint",
                "reason": "health check",
                "affects": ["auth"],
                "invariants_touched": [],
                "assumes": assumes_list
            },
            "verdict": "AMBIGUOUS", "malformed_intent": False,
            "timestamp": datetime.utcnow().isoformat()
        }
    ]
    with open(log_path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    return log_path


# ---------- Extraction ----------

def test_extract_assumptions_basic(tmp_path):
    write_log(tmp_path, "ext1", ["JWT middleware active", "VPC enforces access"])
    results = extract_assumptions("ext1", log_dir=str(tmp_path))
    assert len(results) == 2
    assert results[0]["assumption"] == "JWT middleware active"
    assert results[0]["call_id"] == 1


def test_extract_assumptions_deduplicates(tmp_path):
    log_path = tmp_path / "session_dedup.jsonl"
    events = [
        {"event": "session_start", "session_id": "dedup", "timestamp": datetime.utcnow().isoformat()},
        {"event": "tool_call", "call_id": 1, "tool": "vigil_create_file", "file": "a.py",
         "intent": {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [],
                    "assumes": ["JWT middleware active"]},
         "verdict": "SKIP", "malformed_intent": False, "timestamp": datetime.utcnow().isoformat()},
        {"event": "tool_call", "call_id": 2, "tool": "vigil_create_file", "file": "b.py",
         "intent": {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [],
                    "assumes": ["JWT middleware active"]},  # duplicate
         "verdict": "SKIP", "malformed_intent": False, "timestamp": datetime.utcnow().isoformat()},
    ]
    with open(log_path, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    results = extract_assumptions("dedup", log_dir=str(tmp_path))
    assert len(results) == 1  # deduplicated


def test_extract_assumptions_empty_log(tmp_path):
    log_path = tmp_path / "session_empty.jsonl"
    log_path.write_text(json.dumps({"event": "session_start", "session_id": "empty",
                                     "timestamp": datetime.utcnow().isoformat()}) + "\n")
    results = extract_assumptions("empty", log_dir=str(tmp_path))
    assert results == []


def test_extract_assumptions_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        extract_assumptions("nonexistent", log_dir=str(tmp_path))


# ---------- Search term extraction ----------

def test_extract_search_terms_filters_stopwords():
    terms = _extract_search_terms("JWT middleware is active on all routes")
    assert "jwt" in terms
    assert "middleware" in terms
    assert "active" not in terms  # filtered
    assert "is" not in terms
    assert "on" not in terms


def test_extract_search_terms_short_words_filtered():
    terms = _extract_search_terms("auth is done by the API gateway")
    assert "auth" in terms
    assert "gateway" in terms
    assert "is" not in terms
    # "by" and "the" filtered by length


# ---------- Directory finding ----------

def test_find_relevant_dirs_jwt(tmp_path):
    # Create some dirs
    (tmp_path / "middleware").mkdir()
    (tmp_path / "auth").mkdir()
    (tmp_path / "static").mkdir()

    dirs = _find_relevant_dirs("JWT middleware active", str(tmp_path))
    dir_names = [d.name for d in dirs]
    assert "middleware" in dir_names
    assert "auth" in dir_names
    assert "static" not in dir_names  # not in JWT keyword map


def test_find_relevant_dirs_no_match_uses_defaults(tmp_path):
    (tmp_path / "src").mkdir()
    dirs = _find_relevant_dirs("completely unrecognized assumption xyz", str(tmp_path))
    dir_names = [d.name for d in dirs]
    assert "src" in dir_names


# ---------- Implementation pattern detection ----------

def test_check_implementation_patterns_finds_decorator():
    snippets = [
        (Path("routes.py"), "@require_auth\ndef admin_delete(user_id):\n    db.delete(user_id)")
    ]
    assert _check_implementation_patterns(snippets)


def test_check_implementation_patterns_finds_jwt():
    snippets = [
        (Path("auth.py"), "payload = jwt.decode(token, SECRET, algorithms=['HS256'])")
    ]
    assert _check_implementation_patterns(snippets)


def test_check_implementation_patterns_no_signal():
    snippets = [
        (Path("utils.py"), "def format_price(p):\n    return f'${p:.2f}'")
    ]
    assert not _check_implementation_patterns(snippets)


# ---------- Static scan ----------

def test_scan_finds_relevant_code(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    auth_file = src / "auth.py"
    auth_file.write_text("from jose import jwt\n\ndef verify_token(token):\n    return jwt.decode(token, SECRET)\n")

    dirs = [src]
    snippets = _scan_directory(dirs, "JWT token verification")
    assert len(snippets) > 0
    assert any("jwt" in s.lower() for _, s in snippets)


def test_scan_returns_empty_for_no_match(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "utils.py").write_text("def add(a, b): return a + b\n")

    snippets = _scan_directory([src], "JWT middleware authentication")
    assert snippets == []


# ---------- Report formatting ----------

def test_format_report_with_unverified():
    results = [
        AssumptionResult(
            assumption="VPC enforces admin-only access",
            source_file="src/internal.py",
            call_id=3,
            status="UNVERIFIED",
            confidence="HIGH",
            evidence="No implementation found matching assumption keywords.",
            scope="CODEBASE"
        )
    ]
    report = format_verification_report(results, "testsession")
    assert "UNVERIFIED" in report
    assert "VPC enforces admin-only access" in report
    assert "Call #3" in report
    assert "Unverified Assumptions" in report


def test_format_report_empty():
    report = format_verification_report([], "empty")
    assert "No assumptions found" in report


def test_format_report_verified_only():
    results = [
        AssumptionResult(
            assumption="Rate limiting configured",
            source_file="src/routes.py",
            call_id=2,
            status="VERIFIED",
            confidence="HIGH",
            evidence="Implementation pattern found in: routes.py"
        )
    ]
    report = format_verification_report(results, "s1")
    assert "Verified" in report
    assert "Unverified Assumptions" not in report


# ---------- Integration: full verify flow (no LLM) ----------

@pytest.mark.asyncio
async def test_verify_unverified_assumption(tmp_path, monkeypatch):
    """An assumption with no matching code → UNVERIFIED without LLM call."""
    write_log(tmp_path, "v1", ["JWT middleware active on all /api/v1/ routes"])

    # No middleware dir exists in tmp_path — scan returns empty
    from audit.verifier import verify_assumptions
    results = await verify_assumptions(
        session_id="v1",
        project_root=str(tmp_path),
        log_dir=str(tmp_path)
    )

    assert len(results) == 1
    assert results[0].status == "UNVERIFIED"
    assert results[0].confidence == "HIGH"


@pytest.mark.asyncio
async def test_verify_verified_assumption_via_pattern(tmp_path):
    """An assumption with a strong static signal → VERIFIED without LLM call."""
    # Create middleware file with JWT pattern
    middleware_dir = tmp_path / "middleware"
    middleware_dir.mkdir()
    (middleware_dir / "auth.py").write_text(
        "from jose import jwt\n\n@require_auth\ndef verify_token(token):\n    return jwt.decode(token, SECRET)\n"
    )

    write_log(tmp_path, "v2", ["JWT middleware active on all routes"])

    from audit.verifier import verify_assumptions
    results = await verify_assumptions(
        session_id="v2",
        project_root=str(tmp_path),
        log_dir=str(tmp_path)
    )

    assert len(results) == 1
    assert results[0].status == "VERIFIED"
    assert results[0].confidence == "HIGH"
