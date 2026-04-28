# Vigil — Phase 4: Tier 2 Async Analysis & pending_block Injection

## What This Phase Builds

The deep reasoning layer. By end of this phase:
- Tier 2 (frontier model, async) runs on all `AMBIGUOUS` cases in parallel with the file write
- Tier 2 has the full accumulated session context: brief + all prior diffs + prior intents + verdicts
- Tier 2 findings are stored in `pending_block` on the interceptor instance
- At every subsequent tool call, `pending_block` is checked first — if set, it is injected before the new call proceeds
- Malformed INTENT patterns (3+ malformed calls in session) are escalated to Tier 2 directly
- Context compression kicks in at 100 entries to keep Tier 2 token cost bounded
- The audit log records `detected_at` and `injected_at` call IDs for deferred findings

---

## Prerequisites

Phase 3 complete. Classifier working. Tier 1 blocking and passing. AMBIGUOUS cases let through with a log note. All Phase 3 tests passing.

---

## `server/tier2.py` — Frontier Model Analysis

Async. The tool call it was triggered on has already been written to disk by the time this returns. If it finds a BLOCK, that block is stored and injected at the NEXT tool call.

```python
import anthropic
import os
import json
from pathlib import Path
from models.intent import IntentMessage
from models.verdict import Verdict
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief

_client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

def _load_prompt() -> str:
    return Path("prompts/tier2.txt").read_text()


async def analyze_async(
    diff: str,
    intent: IntentMessage,
    brief: ArchitectureBrief,
    history: list[ContextEntry],
    call_id: int
) -> Verdict:
    """
    Async Tier 2 analysis. Runs in parallel with the file write.
    Returns a Verdict — if BLOCK, caller stores it in pending_block.

    Uses the full accumulated session history for cross-context reasoning.
    """
    system_prompt = _load_prompt()
    user_message = _build_tier2_message(diff, intent, brief, history, call_id)

    try:
        response = await _client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}]
        )

        raw = response.content[0].text.strip()
        verdict = _parse_verdict(raw)
        verdict.detected_at = call_id
        return verdict

    except Exception as e:
        # On failure, return APPROVE — Tier 2 failures must never block
        # (Tier 1 already let this through, double-failure = accept)
        return Verdict(
            verdict="APPROVE",
            finding=f"Tier 2 analysis failed: {str(e)[:100]}. Defaulting to APPROVE.",
        )


def _build_tier2_message(
    diff: str,
    intent: IntentMessage,
    brief: ArchitectureBrief,
    history: list[ContextEntry],
    call_id: int
) -> str:
    """
    Builds the full context message for Tier 2.
    Includes the brief, all prior session entries, and the current diff.
    """
    parts = []

    # Architecture Brief
    parts.append("## ARCHITECTURE BRIEF")
    parts.append(brief.raw_markdown)
    parts.append("")

    # Session history (all prior entries)
    if history:
        parts.append("## SESSION HISTORY")
        for entry in history:
            parts.append(f"### Call #{entry.call_id} — {entry.tool} → {entry.file_path}")
            parts.append(f"Verdict: {entry.verdict}")
            if entry.full_verdict and entry.full_verdict.finding:
                parts.append(f"Finding: {entry.full_verdict.finding}")
            parts.append(f"INTENT: {entry.intent.intent}")
            parts.append(f"affects: {entry.intent.affects}")
            parts.append(f"assumes: {entry.intent.assumes}")
            if entry.malformed_intent:
                parts.append("⚠ MALFORMED INTENT: affects was inferred from diff, not agent-provided")
            parts.append("DIFF (truncated to 800 chars):")
            parts.append(entry.diff[:800])
            parts.append("")

    # Current call
    parts.append(f"## CURRENT CALL (#{call_id}) — FLAGGED AMBIGUOUS BY TIER 1")
    parts.append(f"INTENT: {intent.intent}")
    parts.append(f"reason: {intent.reason}")
    parts.append(f"affects: {intent.affects}")
    parts.append(f"invariants_touched: {intent.invariants_touched}")
    parts.append(f"assumes: {intent.assumes}")
    parts.append("DIFF:")
    parts.append(diff[:6000])  # Tier 2 gets more context than Tier 1

    return "\n".join(parts)


def _parse_verdict(raw: str) -> Verdict:
    """
    Parses JSON verdict from Tier 2. Defaults to APPROVE on parse failure.
    Tier 2 failures should never block — better to miss than false-positive.
    """
    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        clean = clean.strip()

        data = json.loads(clean)

        return Verdict(
            verdict=data.get("verdict", "APPROVE"),
            severity=data.get("severity"),
            vulnerability_class=data.get("vulnerability_class"),
            finding=data.get("finding"),
            fix=data.get("fix"),
            invariant_violated=data.get("invariant_violated"),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return Verdict(
            verdict="APPROVE",
            finding="Tier 2 returned unparseable response. Defaulting to APPROVE.",
        )
```

---

## Context Compression — `server/context.py` (updated)

Add compression logic. At 100 entries, older entries are summarized by a model call. Security decisions (BLOCK, CLEAR_BLOCK) are NEVER compressed — they are always preserved verbatim because Tier 2 needs them for invariant tracking.

```python
import anthropic
import os
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief

_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

COMPRESS_AT = 100       # compress when context reaches this many entries
KEEP_RECENT = 20        # always keep the most recent N entries uncompressed
KEEP_SECURITY = True    # always keep BLOCK and CLEAR_BLOCK entries verbatim


class ContextManager:
    def __init__(self, brief: ArchitectureBrief):
        self.brief = brief
        self.entries: list[ContextEntry] = []
        self._call_counter = 0
        self._compressed_summary: str = ""   # summary of old compressed entries

    def next_call_id(self) -> int:
        self._call_counter += 1
        return self._call_counter

    def append(self, entry: ContextEntry):
        self.entries.append(entry)
        if len(self.entries) >= COMPRESS_AT:
            self._compress()

    def get_history(self) -> list[ContextEntry]:
        """Returns entries for Tier 2 context. Compression reduces this list."""
        return list(self.entries)

    def get_compressed_summary(self) -> str:
        return self._compressed_summary

    def malformed_intent_count(self) -> int:
        return sum(1 for e in self.entries if e.malformed_intent)

    def __len__(self):
        return len(self.entries)

    def _compress(self):
        """
        Compress old entries to reduce Tier 2 context size.
        Keeps: last KEEP_RECENT entries + all BLOCK/CLEAR_BLOCK entries.
        Summarizes: everything else.
        """
        # Entries to always keep
        security_entries = [
            e for e in self.entries
            if e.verdict in ("BLOCK", "CLEAR_BLOCK")
        ]
        recent_entries = self.entries[-KEEP_RECENT:]

        # Entries to compress (everything else)
        keep_ids = {e.call_id for e in security_entries + recent_entries}
        to_compress = [e for e in self.entries if e.call_id not in keep_ids]

        if not to_compress:
            return

        # Build a summary of the compressed entries
        summary_input = "\n\n".join([
            f"Call #{e.call_id}: {e.tool} → {e.file_path}\n"
            f"Verdict: {e.verdict} | affects: {e.intent.affects}\n"
            f"Intent: {e.intent.intent}"
            for e in to_compress
        ])

        try:
            response = _client.messages.create(
                model="claude-haiku-4-5",
                max_tokens=512,
                system=(
                    "Summarize these coding session entries for a security watcher. "
                    "Preserve: file paths touched, security domains affected, any approved "
                    "security-relevant decisions. Discard: routine logic changes, boilerplate, "
                    "irrelevant SKIPs. Output a compact paragraph."
                ),
                messages=[{"role": "user", "content": summary_input}]
            )
            new_summary = response.content[0].text.strip()
            # Append to any prior summary
            if self._compressed_summary:
                self._compressed_summary += "\n\n" + new_summary
            else:
                self._compressed_summary = new_summary
        except Exception:
            # Compression failure is non-fatal — keep entries uncompressed
            return

        # Replace full entry list with: compressed_summary + security + recent
        self.entries = security_entries + recent_entries
```

---

## Updating `server/interceptor.py` — Full Phase 4 Version

Replace the Phase 3 `handle` method entirely. This is the complete final version of the interceptor.

```python
import asyncio
from models.intent import IntentMessage
from models.verdict import Verdict, ToolCallResult
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief
from audit.logger import AuditLogger
from server.context import ContextManager
from server.classifier import classify
from server.tier1 import analyze_sync
from server.tier2 import analyze_async


class Interceptor:
    def __init__(
        self,
        brief: ArchitectureBrief,
        context: ContextManager,
        logger: AuditLogger,
        session_id: str
    ):
        self.brief = brief
        self.context = context
        self.logger = logger
        self.session_id = session_id
        self.pending_block: Verdict | None = None   # deferred Tier 2 finding

    async def handle(
        self,
        tool: str,
        file_path: str,
        params: dict,
        intent_raw: dict
    ) -> str:
        call_id = self.context.next_call_id()

        # Step 0: Inject any pending Tier 2 block from a prior call
        if self.pending_block:
            block = self.pending_block
            self.pending_block = None
            block.injected_at = call_id
            self.logger.log_tool_call(ContextEntry(
                call_id=call_id,
                tool=tool,
                file_path=file_path,
                diff="[deferred block injection — current call halted]",
                intent=IntentMessage(**intent_raw),
                verdict="BLOCK",
                full_verdict=block,
            ))
            return self._format_deferred_block(block)

        intent = IntentMessage(**intent_raw)
        diff = self._extract_diff(tool, params)

        # Step 1: INTENT Classifier
        relevant, effective_affects, used_inference = classify(intent, diff)

        if used_inference:
            self.logger.log_malformed_intent(
                call_id=call_id,
                tool=tool,
                file_path=file_path,
                reason="affects empty or malformed; inferred from diff"
            )
            malformed_count = self.context.malformed_intent_count()
            if malformed_count >= 3:
                # Escalate pattern to Tier 2 — suspicious behaviour
                relevant = True
                self.logger.log_malformed_intent(
                    call_id=call_id, tool=tool, file_path=file_path,
                    reason=f"PATTERN ESCALATION: {malformed_count+1} malformed INTENT calls — routing to Tier 2"
                )

        if not relevant:
            entry = ContextEntry(
                call_id=call_id, tool=tool, file_path=file_path,
                diff=diff, intent=intent, verdict="SKIP",
                malformed_intent=used_inference
            )
            self.context.append(entry)
            self.logger.log_tool_call(entry)
            self._execute(tool, params)
            return "[Vigil] SKIP — not security relevant"

        # Step 2: Tier 1 — sync, blocks current call
        tier1_verdict = analyze_sync(
            diff=diff, intent=intent,
            brief=self.brief, effective_affects=effective_affects
        )

        if tier1_verdict.verdict == "CLEAR_BLOCK":
            entry = ContextEntry(
                call_id=call_id, tool=tool, file_path=file_path,
                diff=diff, intent=intent, verdict="CLEAR_BLOCK",
                full_verdict=tier1_verdict, malformed_intent=used_inference
            )
            self.context.append(entry)
            self.logger.log_tool_call(entry)
            # File is NOT written
            return self._format_block_message(tier1_verdict)

        # CLEAR_PASS or AMBIGUOUS — write the file
        self._execute(tool, params)

        entry = ContextEntry(
            call_id=call_id, tool=tool, file_path=file_path,
            diff=diff, intent=intent, verdict=tier1_verdict.verdict,
            full_verdict=tier1_verdict, malformed_intent=used_inference
        )
        self.context.append(entry)
        self.logger.log_tool_call(entry)

        # Step 3: Tier 2 — async, runs in parallel
        if tier1_verdict.verdict == "AMBIGUOUS":
            asyncio.create_task(self._run_tier2(diff, intent, call_id))
            return f"[Vigil] AMBIGUOUS — file written, deep analysis running in background (call #{call_id})"

        return "[Vigil] APPROVE"

    async def _run_tier2(self, diff: str, intent: IntentMessage, call_id: int):
        """Runs Tier 2 async. Stores result in pending_block if BLOCK."""
        try:
            verdict = await analyze_async(
                diff=diff,
                intent=intent,
                brief=self.brief,
                history=self.context.get_history(),
                call_id=call_id
            )
            if verdict.verdict == "BLOCK":
                verdict.detected_at = call_id
                self.pending_block = verdict
                self.logger.log_tool_call(ContextEntry(
                    call_id=call_id,
                    tool="tier2_async_result",
                    file_path="[async]",
                    diff=diff,
                    intent=intent,
                    verdict="BLOCK",
                    full_verdict=verdict,
                ))
        except Exception as e:
            # Tier 2 failure is non-fatal
            self.logger.log_malformed_intent(
                call_id=call_id, tool="tier2", file_path="[async]",
                reason=f"Tier 2 task raised exception: {str(e)[:100]}"
            )

    def _format_deferred_block(self, verdict: Verdict) -> str:
        lines = [
            f"[Vigil] DEFERRED BLOCK — finding from call #{verdict.detected_at}",
            f"Severity: {verdict.severity or 'UNKNOWN'}",
            f"Class: {verdict.vulnerability_class or 'unclassified'}",
            f"Finding: {verdict.finding or 'No details'}",
        ]
        if verdict.fix:
            lines.append(f"Fix: {verdict.fix}")
        if verdict.invariant_violated:
            lines.append(f"Invariant violated: {verdict.invariant_violated}")
        lines.append("")
        lines.append("The code from that call has already been written. You must address")
        lines.append("this finding before making any further changes. The current tool call")
        lines.append("has been halted until you resolve this.")
        return "\n".join(lines)

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

    def _extract_diff(self, tool: str, params: dict) -> str:
        if tool == "vigil_write_file":
            return params.get("content", "")
        elif tool == "vigil_str_replace":
            return f"REMOVED:\n{params.get('old_str', '')}\nADDED:\n{params.get('new_str', '')}"
        elif tool == "vigil_create_file":
            return params.get("file_text", "")
        return ""

    def _execute(self, tool: str, params: dict):
        import os
        path = params["path"]
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)

        if tool in ("vigil_write_file", "vigil_create_file"):
            content = params.get("content") or params.get("file_text", "")
            with open(path, "w") as f:
                f.write(content)
        elif tool == "vigil_str_replace":
            with open(path, "r") as f:
                current = f.read()
            if params["old_str"] not in current:
                raise ValueError(f"old_str not found in {path}")
            updated = current.replace(params["old_str"], params["new_str"], 1)
            with open(path, "w") as f:
                f.write(updated)
```

---

## Tests to Write — `tests/test_phase4.py`

```python
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
```

---

## Key Behaviours to Verify Manually

After all tests pass, run a manual end-to-end test:

1. Start Vigil with `VIGIL_PROJECT_PROMPT="payment service with JWT auth"`
2. Connect Claude Code via `.mcp.json`
3. Ask Claude Code to build a simple endpoint that skips auth "because it's an internal endpoint"
4. Verify:
   - Call #1 (creating the file): AMBIGUOUS returned, file written
   - Tier 2 runs in background (check logs)
   - Call #2 (any subsequent write): DEFERRED BLOCK injected with Tier 2 finding

---

## Completion Criteria for Phase 4

- [ ] `pytest tests/test_phase4.py` passes fully
- [ ] `AMBIGUOUS` cases: `asyncio.create_task` fires, Tier 2 runs, result stored in `pending_block`
- [ ] `pending_block` is injected at the VERY NEXT tool call (before that call proceeds)
- [ ] When `pending_block` is injected, the current tool call is halted — file NOT written
- [ ] `detected_at` and `injected_at` call IDs are correctly set and logged
- [ ] Context compression fires at 100 entries
- [ ] BLOCK/CLEAR_BLOCK entries are never removed by compression
- [ ] Malformed INTENT pattern (3+ calls) escalates to Tier 2 correctly
- [ ] Tier 2 failure (exception in `_run_tier2`) is caught, logged, does NOT propagate
- [ ] Audit log entries have correct `detected_at` / `injected_at` fields for deferred blocks

## What Phase 5 Will Build On

Phase 5 adds the session audit report, a CLI for inspecting session logs, invariant violation summary, and the CLAUDE.md template for integrating Vigil with Claude Code. It also stress-tests the full pipeline end-to-end.
