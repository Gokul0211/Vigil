from pydantic import BaseModel
from datetime import datetime
from .intent import IntentMessage
from .verdict import Verdict, VerdictType


class ContextEntry(BaseModel):
    call_id: int
    tool: str                          # "vigil_write_file" | "vigil_str_replace" | "vigil_create_file"
    file_path: str
    diff: str                          # extracted diff text passed to the analysis tiers
    intent: IntentMessage
    verdict: VerdictType
    full_verdict: Verdict | None = None   # populated when Tier 1/2 returns a structured verdict
    timestamp: datetime | None = None
    malformed_intent: bool = False        # True when diff inference was used instead of declared affects

    def model_post_init(self, __context) -> None:
        # Auto-stamp with UTC time if caller did not supply one
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
