import json
from pathlib import Path
from datetime import datetime
import hashlib
from models.context_entry import ContextEntry


class AuditLogger:
    """Writes a structured JSONL audit trail for a single Vigil session.

    One JSON object per line. File is created at session start and
    appended on every subsequent event.
    """

    def __init__(self, session_id: str, log_dir: str = "logs"):
        self.session_id = session_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / f"session_{session_id}.jsonl"
        self._write_session_start()

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def log_tool_call(self, entry: ContextEntry) -> None:
        """Append one tool-call record to the audit log."""
        diff_bytes = entry.diff.encode("utf-8")
        diff_hash = hashlib.sha256(diff_bytes).hexdigest()[:16]

        # Write full diff to separate file if over preview threshold
        full_diff_path = None
        if len(entry.diff) > 600:
            diff_dir = self.log_dir / "diffs"
            diff_dir.mkdir(exist_ok=True)
            diff_file = diff_dir / f"{self.session_id}_call{entry.call_id}_{diff_hash}.txt"
            diff_file.write_text(entry.diff, encoding="utf-8")
            full_diff_path = str(diff_file)

        record = {
            "event": "tool_call",
            "call_id": entry.call_id,
            "tool": entry.tool,
            "file": entry.file_path,
            "diff_preview": entry.diff[:600],
            "diff_hash": diff_hash,
            "full_diff_path": full_diff_path,
            "intent": entry.intent.model_dump(),
            "verdict": entry.verdict,
            "malformed_intent": entry.malformed_intent,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        }
        # Attach full verdict detail when available (Tier 1 BLOCK or Tier 2 BLOCK)
        if entry.full_verdict:
            record["severity"] = entry.full_verdict.severity
            record["finding"] = entry.full_verdict.finding
            record["fix"] = entry.full_verdict.fix
            record["invariant_violated"] = entry.full_verdict.invariant_violated
        self._append(record)

    def log_brief_generated(self, brief_markdown: str) -> None:
        """Record that an Architecture Brief was generated for this session."""
        self._append({
            "event": "brief_generated",
            "session_id": self.session_id,
            "brief_preview": brief_markdown[:500],  # first 500 chars only
            "timestamp": datetime.utcnow().isoformat(),
        })

    def log_malformed_intent(
        self, call_id: int, tool: str, file_path: str, reason: str
    ) -> None:
        """Record that an INTENT message was empty / garbage on a security-relevant call."""
        self._append({
            "event": "malformed_intent",
            "call_id": call_id,
            "tool": tool,
            "file": file_path,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
        })

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_session_start(self) -> None:
        self._append({
            "event": "session_start",
            "session_id": self.session_id,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def _append(self, record: dict) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
