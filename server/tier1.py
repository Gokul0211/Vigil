import anthropic
import os
import json
from pathlib import Path
from models.intent import IntentMessage
from models.verdict import Verdict
from brief.schema import ArchitectureBrief

_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))


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

    This must stay fast. Do not add retries — if the model call fails,
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
        verdict = _parse_verdict(raw)
        return _validate_invariant(verdict, brief)

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
    # Diff is truncated at 4000 chars for Tier 1 — huge diffs → AMBIGUOUS is fine


def _parse_verdict(raw: str) -> Verdict:
    """
    Parses the JSON response from Tier 1.
    Handles: plain JSON, JSON wrapped in markdown fences, and completely invalid responses.
    Defaults to AMBIGUOUS on any parse failure.
    """
    try:
        clean = raw.strip()
        # Strip markdown code fences if the model added them
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


def _validate_invariant(verdict: Verdict, brief: ArchitectureBrief) -> Verdict:
    """Clear invariant_violated if the ID doesn't exist in the brief."""
    if not verdict.invariant_violated or not brief.invariants:
        return verdict

    valid_ids = [inv.id for inv in brief.invariants]
    if verdict.invariant_violated not in valid_ids:
        verdict.invariant_violated = None

    return verdict
