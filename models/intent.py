from pydantic import BaseModel, field_validator

# All valid security domain values the agent may declare in `affects`
VALID_AFFECTS_DOMAINS = {
    "auth", "crypto", "logging", "data-exposure",
    "input-validation", "file-system", "network", "none", "unknown"
}


class IntentMessage(BaseModel):
    intent: str                    # one-line description of what this code block does
    reason: str                    # why this decision was made
    affects: list[str]             # security domains touched — validated against VALID_AFFECTS_DOMAINS
    invariants_touched: list[str]  # invariant IDs from the brief being intentionally relaxed
    assumes: list[str]             # external guarantees being relied on

    @field_validator("affects", mode="before")
    @classmethod
    def normalize_affects(cls, v):
        # lowercase, strip whitespace, deduplicate — preserves order via dict insertion
        return list({a.strip().lower() for a in v}) if v else []

    @property
    def is_empty(self) -> bool:
        """True if the agent passed no meaningful INTENT data at all."""
        return (
            not self.intent.strip()
            and not self.affects
            and not self.invariants_touched
            and not self.assumes
        )

    @property
    def is_malformed(self) -> bool:
        """True if affects is non-empty but contains NO recognized domain values."""
        return bool(self.affects) and not any(
            a in VALID_AFFECTS_DOMAINS for a in self.affects
        )
