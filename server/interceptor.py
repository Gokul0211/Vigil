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

    def _format_response(self, result: ToolCallResult) -> str:
        """Format the ToolCallResult as a string returned to the coding agent."""
        if result.blocked or not result.allowed:
            prefix = "[Vigil] DEFERRED BLOCK" if result.deferred else "[Vigil] BLOCK"
            v = result.verdict
            lines = [
                f"{prefix} — {v.severity or 'UNKNOWN'} severity",
                f"Finding: {v.finding}",
                f"Fix: {v.fix}",
            ]
            if v.invariant_violated:
                lines.append(f"Invariant violated: {v.invariant_violated}")
            return "\n".join(lines)
        return result.message
