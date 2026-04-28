import anthropic
import os
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief

_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

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
