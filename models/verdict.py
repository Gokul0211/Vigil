from pydantic import BaseModel
from typing import Literal

# Tier 1 returns CLEAR_BLOCK / CLEAR_PASS / AMBIGUOUS
# Tier 2 returns APPROVE / BLOCK
# Classifier short-circuits with SKIP
VerdictType = Literal["CLEAR_BLOCK", "CLEAR_PASS", "AMBIGUOUS", "APPROVE", "BLOCK", "SKIP", "WARN"]
SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None


class Verdict(BaseModel):
    verdict: VerdictType
    severity: SeverityLevel = None
    vulnerability_class: str | None = None   # e.g. "business-logic/auth-bypass"
    finding: str | None = None               # human-readable explanation
    fix: str | None = None                   # suggested remediation
    invariant_violated: str | None = None    # invariant ID from the brief, if any
    detected_at: int | None = None           # call_id when Tier 2 generated the finding
    injected_at: int | None = None           # call_id when Tier 2 finding was injected


class ToolCallResult(BaseModel):
    """
    Returned to the coding agent after handle_tool_call completes.
    - blocked=True  → agent must fix the finding before proceeding
    - deferred=True → a prior Tier 2 finding is being injected at this boundary
    """
    allowed: bool
    blocked: bool = False
    warned: bool = False          # True when finding is below block threshold
    deferred: bool = False        # True when injecting a pending Tier 2 block
    verdict: Verdict | None = None
    message: str = ""             # human-readable message returned to the agent
