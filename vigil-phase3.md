# Vigil — Phase 3: INTENT Classifier & Tier 1 Fast Model

## What This Phase Builds

The first real security analysis layer. By end of this phase:
- The INTENT classifier routes every tool call into `SKIP` or `SECURITY_RELEVANT`
- Malformed/empty INTENT fields are detected and `affects` is inferred from the diff
- Malformed INTENT patterns are logged and tracked per session
- Tier 1 (fast model, sync, <200ms) runs on all `SECURITY_RELEVANT` calls
- Tier 1 returns `CLEAR_BLOCK`, `CLEAR_PASS`, or `AMBIGUOUS`
- `CLEAR_BLOCK` halts the tool call immediately — the file is NOT written
- `CLEAR_PASS` and `AMBIGUOUS` let the tool call through (Tier 2 handles `AMBIGUOUS` in Phase 4)
- The interceptor stub comments from Phase 2 are replaced with real logic

No Tier 2 yet. `AMBIGUOUS` cases are let through with a log note — Phase 4 wires the async path.

---

## Prerequisites

Phase 2 complete. MCP server starts. Stub interceptor approves everything. All Phase 2 tests pass.

---

## `server/classifier.py` — INTENT Classifier

This runs before any model. Pure Python, no API calls, near-zero latency. Two jobs:

1. Determine if a tool call is security-relevant (should it reach Tier 1?)
2. Detect malformed/empty INTENT and infer `affects` from the diff as a fallback

```python
from models.intent import IntentMessage

# Domains that make a call security-relevant
SECURITY_RELEVANT_DOMAINS = {
    "auth", "crypto", "logging", "data-exposure",
    "input-validation", "file-system", "network"
}

# Keyword sets for diff-based inference
# Used when the agent passes empty or garbage `affects`
SENSITIVE_KEYWORDS: dict[str, list[str]] = {
    "auth": [
        "jwt", "token", "session", "login", "logout", "password", "bearer",
        "authenticate", "authorize", "oauth", "api_key", "apikey", "secret_key"
    ],
    "crypto": [
        "encrypt", "decrypt", "hash", "hmac", "aes", "rsa", "sha256",
        "pbkdf2", "bcrypt", "scrypt", "argon2", "cipher", "iv", "nonce"
    ],
    "logging": [
        "console.log", "logger.", "log.info", "log.debug", "log.error",
        "log.warn", "print(", "logging.", "winston", "pino", "bunyan",
        "structlog", "sentry"
    ],
    "data-exposure": [
        "pii", "email", "card", "ssn", "address", "phone", "dob",
        "date_of_birth", "credit_card", "cvv", "account_number",
        "social_security", "passport", "license"
    ],
    "input-validation": [
        "request.body", "req.body", "req.query", "req.params",
        "user_input", "form.get", "request.form", "request.args",
        "request.json", "request.data", "getattr(request",
        "flask.request", "fastapi.request"
    ],
    "file-system": [
        "open(", "os.path", "pathlib", "shutil", "os.remove",
        "os.rename", "os.makedirs", "file.write", "file.read",
        "subprocess", "exec(", "eval("
    ],
    "network": [
        "requests.get", "requests.post", "httpx.", "aiohttp.",
        "fetch(", "axios.", "urllib", "socket.", "http.client",
        "grpc.", "websocket"
    ],
}

# High-confidence dangerous patterns — these alone make a call security-relevant
# regardless of what `affects` says
ALWAYS_RELEVANT_PATTERNS = [
    "eval(",
    "exec(",
    "os.system(",
    "subprocess.call(",
    "subprocess.run(",
    "__import__(",
    "pickle.loads(",
    "yaml.load(",          # yaml.safe_load is fine, yaml.load is not
    "deserialize(",
    "marshal.loads(",
]


def is_security_relevant(intent: IntentMessage, diff: str) -> bool:
    """
    Returns True if this tool call should be routed to Tier 1.
    Returns False if it can be skipped entirely.

    A call is security-relevant if ANY of these are true:
    - intent.affects contains at least one known security domain
    - intent.invariants_touched is non-empty
    - intent.assumes is non-empty (unverified assumptions are always worth checking)
    - diff contains an always-relevant pattern (eval, exec, etc.)
    - diff-based keyword inference returns non-empty results
    """
    # Explicit affects from agent
    if any(d in SECURITY_RELEVANT_DOMAINS for d in intent.affects):
        return True

    # Agent flagged invariants or assumptions
    if intent.invariants_touched:
        return True
    if intent.assumes:
        return True

    # Always-relevant patterns in diff
    diff_lower = diff.lower()
    if any(p in diff_lower for p in ALWAYS_RELEVANT_PATTERNS):
        return True

    # Keyword-based inference
    inferred = infer_affects_from_diff(diff)
    if inferred and inferred != ["unknown"]:
        return True

    return False


def infer_affects_from_diff(diff: str) -> list[str]:
    """
    Infers security-relevant domains from the diff text.
    Used when the agent passes empty or garbage `affects`.

    Returns a list of domain strings, or ["unknown"] if nothing matched.
    "unknown" is not safe to skip — it still routes to Tier 1.
    """
    found = []
    diff_lower = diff.lower()
    for domain, keywords in SENSITIVE_KEYWORDS.items():
        if any(kw in diff_lower for kw in keywords):
            found.append(domain)
    return found if found else ["unknown"]


def classify(intent: IntentMessage, diff: str) -> tuple[bool, list[str], bool]:
    """
    Main entry point for the classifier.

    Returns:
        (should_route_to_tier1: bool, effective_affects: list[str], used_inference: bool)

    `used_inference` is True when the agent's `affects` was empty/malformed and
    we fell back to diff-based inference. This is logged as a malformed intent signal.
    """
    used_inference = False
    effective_affects = list(intent.affects)

    # Check if intent is empty or malformed
    if intent.is_empty or intent.is_malformed or not intent.affects:
        inferred = infer_affects_from_diff(diff)
        effective_affects = inferred
        used_inference = True

    # Build a temporary intent with effective_affects for the relevance check
    # (we don't mutate the original intent object)
    check_intent = intent.model_copy(update={"affects": effective_affects})
    relevant = is_security_relevant(check_intent, diff)

    return relevant, effective_affects, used_inference
```

---

## `server/tier1.py` — Fast Model Analysis

Sync call to a small, fast model. Should return in under 200ms. Uses `claude-haiku-4-5` by default — swap for Gemini Flash if latency is too high.

**Important constraint:** Tier 1 must be HIGH CONFIDENCE ONLY. If it's not sure, it returns `AMBIGUOUS`. It must never block on speculation. A false positive (blocking legitimate code) is worse than a false negative (letting Tier 2 handle it).

```python
import anthropic
import os
import json
from pathlib import Path
from models.intent import IntentMessage
from models.verdict import Verdict
from brief.schema import ArchitectureBrief

_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

def _load_prompt() -> str:
    return Path("prompts/tier1.txt").read_text()


def analyze_sync(
    diff: str,
    intent: IntentMessage,
    brief: ArchitectureBrief,
    effective_affects: list[str]
) -> Verdict:
    """
    Synchronous Tier 1 analysis. Blocks the current tool call.
    Returns a Verdict with CLEAR_BLOCK, CLEAR_PASS, or AMBIGUOUS.

    This must stay fast. Do not add retries here — if the model call fails,
    return AMBIGUOUS and let Tier 2 handle it.
    """
    system_prompt = _load_prompt()

    user_message = _build_tier1_message(diff, intent, brief, effective_affects)

    try:
        response = _client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=512,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}]
        )

        raw = response.content[0].text.strip()
        return _parse_verdict(raw)

    except Exception as e:
        # On any model failure, return AMBIGUOUS — never block on an error
        return Verdict(
            verdict="AMBIGUOUS",
            finding=f"Tier 1 model call failed: {str(e)[:100]}. Routing to Tier 2.",
            severity=None
        )


def _build_tier1_message(
    diff: str,
    intent: IntentMessage,
    brief: ArchitectureBrief,
    effective_affects: list[str]
) -> str:
    return f"""## ARCHITECTURE BRIEF
{brief.raw_markdown}

---

## INTENT
- intent: {intent.intent}
- reason: {intent.reason}
- affects: {effective_affects}
- invariants_touched: {intent.invariants_touched}
- assumes: {intent.assumes}

---

## DIFF
{diff[:4000]}
"""
    # Truncate diff at 4000 chars for Tier 1 — if the diff is huge, AMBIGUOUS is fine


def _parse_verdict(raw: str) -> Verdict:
    """
    Parses the JSON response from Tier 1.
    If the model returns malformed JSON, defaults to AMBIGUOUS.
    """
    try:
        # Strip markdown code fences if the model added them
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        clean = clean.strip()

        data = json.loads(clean)

        return Verdict(
            verdict=data.get("verdict", "AMBIGUOUS"),
            severity=data.get("severity"),
            finding=data.get("finding"),
            fix=data.get("fix"),
            invariant_violated=data.get("invariant_violated"),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return Verdict(
            verdict="AMBIGUOUS",
            finding="Tier 1 returned unparseable response. Routing to Tier 2.",
            severity=None
        )
```

---

## Updating `server/interceptor.py`

Replace the Phase 2 stub comment block with the real classifier + Tier 1 logic. The `handle` method becomes:

```python
async def handle(
    self,
    tool: str,
    file_path: str,
    params: dict,
    intent_raw: dict
) -> str:
    from server.classifier import classify
    from server.tier1 import analyze_sync

    call_id = self.context.next_call_id()
    intent = IntentMessage(**intent_raw)
    diff = self._extract_diff(tool, params)

    # --- INTENT Classifier ---
    relevant, effective_affects, used_inference = classify(intent, diff)

    if used_inference:
        # Agent passed empty/malformed INTENT — log it
        self.logger.log_malformed_intent(
            call_id=call_id,
            tool=tool,
            file_path=file_path,
            reason="affects was empty or malformed; inferred from diff"
        )
        # Check malformed pattern escalation (Phase 4 will wire Tier 2 here)
        malformed_count = self.context.malformed_intent_count()
        if malformed_count >= 3:
            # Pattern detected — for now, just log. Phase 4 escalates to Tier 2.
            self.logger.log_malformed_intent(
                call_id=call_id,
                tool=tool,
                file_path=file_path,
                reason=f"PATTERN: {malformed_count+1} malformed INTENT calls in session — suspicious"
            )

    if not relevant:
        # SKIP — not security relevant
        entry = ContextEntry(
            call_id=call_id, tool=tool, file_path=file_path,
            diff=diff, intent=intent, verdict="SKIP",
            malformed_intent=used_inference
        )
        self.context.append(entry)
        self.logger.log_tool_call(entry)
        self._execute(tool, params)
        return "[Vigil] SKIP — not security relevant"

    # --- Tier 1: Fast Model (sync, blocks current call) ---
    tier1_verdict = analyze_sync(
        diff=diff,
        intent=intent,
        brief=self.brief,
        effective_affects=effective_affects
    )

    if tier1_verdict.verdict == "CLEAR_BLOCK":
        # Block — do NOT execute the file write
        entry = ContextEntry(
            call_id=call_id, tool=tool, file_path=file_path,
            diff=diff, intent=intent, verdict="CLEAR_BLOCK",
            full_verdict=tier1_verdict, malformed_intent=used_inference
        )
        self.context.append(entry)
        self.logger.log_tool_call(entry)
        result = ToolCallResult(
            allowed=False, blocked=True,
            verdict=tier1_verdict,
            message=self._format_block_message(tier1_verdict)
        )
        return self._format_response(result)

    # CLEAR_PASS or AMBIGUOUS — execute the file write
    self._execute(tool, params)

    entry = ContextEntry(
        call_id=call_id, tool=tool, file_path=file_path,
        diff=diff, intent=intent, verdict=tier1_verdict.verdict,
        full_verdict=tier1_verdict, malformed_intent=used_inference
    )
    self.context.append(entry)
    self.logger.log_tool_call(entry)

    if tier1_verdict.verdict == "AMBIGUOUS":
        # --- Phase 4 will insert: asyncio.create_task(self._run_tier2(...)) here ---
        return f"[Vigil] AMBIGUOUS — file written, queued for deep analysis (call #{call_id})"

    return "[Vigil] APPROVE"


def _format_block_message(self, verdict: Verdict) -> str:
    lines = [
        f"[Vigil] BLOCK — {verdict.severity or 'UNKNOWN'} severity",
        f"Finding: {verdict.finding or 'No details'}",
    ]
    if verdict.fix:
        lines.append(f"Fix: {verdict.fix}")
    if verdict.invariant_violated:
        lines.append(f"Invariant violated: {verdict.invariant_violated}")
    lines.append("The file was NOT written. Address this finding before proceeding.")
    return "\n".join(lines)
```

---

## Tests to Write — `tests/test_phase3.py`

```python
import pytest
from server.classifier import classify, infer_affects_from_diff, is_security_relevant
from server.tier1 import _parse_verdict, _build_tier1_message
from models.intent import IntentMessage
from models.verdict import Verdict

# ---------- Classifier tests ----------

def make_intent(**kwargs):
    defaults = {"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []}
    defaults.update(kwargs)
    return IntentMessage(**defaults)

def test_classifier_skips_irrelevant():
    intent = make_intent(affects=[])
    diff = "x = 1\nprint('hello')\n"
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

    # Monkeypatch Tier 1 to return CLEAR_BLOCK
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
```

---

## Calibration Notes for Tier 1

The Tier 1 prompt (in `prompts/tier1.txt`) must communicate exactly what "high confidence" means. Key additions beyond what the Phase 1 prompt file says:

Add these examples to `tier1.txt` (as a few-shot section at the bottom):

```
## Examples

DIFF: API_KEY = "sk-prod-1a2b3c4d5e6f"
INTENT affects: []
→ CLEAR_BLOCK (CRITICAL): Hardcoded API key in source.

DIFF: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
INTENT affects: ["input-validation"]
→ CLEAR_BLOCK (HIGH): Unsanitized user input in SQL query — SQL injection risk.

DIFF: logger.info(f"Processing payment for card: {card_number}")
INTENT affects: ["logging"]
→ CLEAR_BLOCK (HIGH): Payment data written to log.

DIFF: result = await db.query("SELECT * FROM products WHERE active = true")
INTENT affects: []
→ CLEAR_PASS: Hardcoded query, no user input, no sensitive data.

DIFF: def get_user(user_id): return db.get(user_id)
INTENT affects: ["auth"], assumes: ["auth middleware validates before this"]
→ AMBIGUOUS: Agent claims auth handled upstream but no auth check in diff. Needs context verification.
```

---

## Completion Criteria for Phase 3

- [ ] `pytest tests/test_phase3.py` passes fully
- [ ] Security-irrelevant tool calls (pure logic, no sensitive patterns) are logged as SKIP
- [ ] A diff with a hardcoded API key → `CLEAR_BLOCK`, file NOT written
- [ ] A diff with unsanitized SQL → `CLEAR_BLOCK`, file NOT written
- [ ] A diff with `eval(user_input)` → `CLEAR_BLOCK` even with empty `affects`
- [ ] Malformed INTENT (empty affects + security-relevant diff) → classified correctly via inference
- [ ] 3+ malformed INTENT calls in a session → pattern logged
- [ ] Tier 1 model failure (network error, timeout) → returns `AMBIGUOUS`, does NOT block
- [ ] `AMBIGUOUS` cases: file IS written, message says "queued for deep analysis"

## What Phase 4 Will Build On

Phase 4 replaces the `# Phase 4 will insert` comment in `interceptor.py`. It wires:
- `pending_block` storage and injection at next tool call boundary
- `asyncio.create_task(self._run_tier2(...))` for AMBIGUOUS cases
- `tier2.py` with the frontier model and full accumulated context
- Malformed INTENT pattern escalation to Tier 2
