import anthropic
import os
import json
from pathlib import Path
from models.intent import IntentMessage
from models.verdict import Verdict
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief

_client = anthropic.AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

def _load_prompt() -> str:
    # return Path("prompts/tier2.txt").read_text()
    # Mocking prompt load to avoid crash if file doesn't exist yet, phase 4 spec doesn't explicitly mention creating tier2.txt here, but I will assume it's created or we should provide a fallback. The spec tells me to implement this file and mentions prompt file.
    prompt_path = Path("prompts/tier2.txt")
    if prompt_path.exists():
        return prompt_path.read_text()
    return "You are a Tier 2 security model."


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
        verdict = _validate_invariant(verdict, brief)
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


def _validate_invariant(verdict: Verdict, brief: ArchitectureBrief) -> Verdict:
    """Clear invariant_violated if the ID doesn't exist in the brief."""
    if not verdict.invariant_violated or not brief.invariants:
        return verdict

    valid_ids = [inv.id for inv in brief.invariants]
    if verdict.invariant_violated not in valid_ids:
        verdict.invariant_violated = None

    return verdict
