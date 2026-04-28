import pytest
from server.classifier import classify, infer_affects_from_diff, is_security_relevant
from server.tier1 import _parse_verdict, _build_tier1_message
from models.intent import IntentMessage
from models.verdict import Verdict

# ---------- Helpers ----------

def make_intent(**kwargs):
    defaults = {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []}
    defaults.update(kwargs)
    return IntentMessage(**defaults)

# ---------- Classifier tests ----------

def test_classifier_skips_irrelevant():
    intent = make_intent(affects=[])
    diff = "x = 1\ny = x + 2\nresult = x * y\n"  # pure math — no security keywords
    relevant, _, _ = classify(intent, diff)
    assert not relevant

def test_classifier_routes_on_affects():
    intent = make_intent(affects=["auth"])
    diff = "x = 1"
    relevant, _, _ = classify(intent, diff)
    assert relevant

def test_classifier_routes_on_assumes():
    intent = make_intent(assumes=["VPC enforces this"])
    diff = "x = 1"
    relevant, _, _ = classify(intent, diff)
    assert relevant

def test_classifier_infers_from_diff():
    intent = make_intent(affects=[])  # empty
    diff = "token = jwt.decode(user_token, SECRET)"
    relevant, effective, used = classify(intent, diff)
    assert relevant
    assert "auth" in effective
    assert used  # inference was triggered

def test_classifier_eval_always_relevant():
    intent = make_intent(affects=[])
    diff = "result = eval(user_input)"
    relevant, _, _ = classify(intent, diff)
    assert relevant

def test_infer_affects_empty_diff():
    result = infer_affects_from_diff("x = 1\ny = 2\n")
    assert result == ["unknown"]

def test_infer_affects_auth():
    result = infer_affects_from_diff("token = jwt.decode(auth_header)")
    assert "auth" in result

def test_infer_affects_multiple_domains():
    result = infer_affects_from_diff("logger.info(email) and jwt.decode(token)")
    assert "auth" in result
    assert "logging" in result
    assert "data-exposure" in result

def test_infer_affects_input_validation():
    result = infer_affects_from_diff("data = request.body.get('user_input')")
    assert "input-validation" in result

# ---------- Tier 1 verdict parsing ----------

def test_parse_verdict_clear_block():
    raw = '{"verdict": "CLEAR_BLOCK", "severity": "HIGH", "finding": "hardcoded secret", "fix": "use env var", "invariant_violated": null}'
    v = _parse_verdict(raw)
    assert v.verdict == "CLEAR_BLOCK"
    assert v.severity == "HIGH"
    assert v.finding == "hardcoded secret"

def test_parse_verdict_ambiguous():
    raw = '{"verdict": "AMBIGUOUS", "severity": null, "finding": null, "fix": null, "invariant_violated": null}'
    v = _parse_verdict(raw)
    assert v.verdict == "AMBIGUOUS"

def test_parse_verdict_malformed_json():
    raw = "this is not json at all"
    v = _parse_verdict(raw)
    assert v.verdict == "AMBIGUOUS"  # safe default

def test_parse_verdict_strips_markdown_fences():
    raw = '```json\n{"verdict": "CLEAR_PASS", "severity": null, "finding": null, "fix": null, "invariant_violated": null}\n```'
    v = _parse_verdict(raw)
    assert v.verdict == "CLEAR_PASS"

# ---------- Integration: interceptor blocks on CLEAR_BLOCK ----------

@pytest.mark.asyncio
async def test_interceptor_blocks_hardcoded_secret(tmp_path, monkeypatch):
    """End-to-end: a file with a hardcoded API key should be blocked."""
    from brief.generator import _parse_brief
    from server.interceptor import Interceptor
    from server.context import ContextManager
    from audit.logger import AuditLogger

    BRIEF_MD = """# Architecture Brief
## System Purpose
Test service.
## Trust Boundaries
- PUBLIC: /api/*
## Auth Model
JWT.
## Data Flows
- User -> DB
## Security Invariants
- [ ] no-hardcoded-secrets: No secrets hardcoded in source
## Sensitive Operations
- API calls
"""
    brief = _parse_brief(BRIEF_MD)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="t1test", log_dir=str(tmp_path))
    interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="t1test")

    # Monkeypatch Tier 1 to return CLEAR_BLOCK without hitting the API
    def mock_analyze(diff, intent, brief, effective_affects):
        return Verdict(verdict="CLEAR_BLOCK", severity="CRITICAL", finding="Hardcoded API key detected", fix="Use environment variable")

    monkeypatch.setattr("server.interceptor.analyze_sync", mock_analyze)

    target = tmp_path / "config.py"
    result = await interceptor.handle(
        tool="vigil_create_file",
        file_path=str(target),
        params={"path": str(target), "file_text": 'API_KEY = "sk-hardcoded-secret-12345"'},
        intent_raw={"intent": "add config", "reason": "testing", "affects": ["auth"], "invariants_touched": [], "assumes": []}
    )

    assert "BLOCK" in result
    assert not target.exists()  # file must NOT have been written
