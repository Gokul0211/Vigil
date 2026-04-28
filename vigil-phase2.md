# Vigil — Phase 2: MCP Server Scaffold & Architecture Brief Generator

## What This Phase Builds

The MCP server comes alive. By end of this phase:
- The three `vigil_*` tools are registered and callable by a coding agent
- Every tool call is received, parsed, and routed to a stub interceptor
- The Architecture Brief is generated at session start via a reasoning model call
- The session is initialized: brief generated → logger started → context manager ready
- The agent gets a real response back (APPROVE stub) for every call

No Tier 1, no Tier 2, no classifier yet. The goal is a working MCP server that a coding agent can actually connect to and call tools on.

---

## Prerequisites

Phase 1 complete. All schemas importable. Prompts exist. Fixtures exist.

---

## The MCP Tool Contract

Vigil exposes exactly three tools. These replace `write_file`, `str_replace`, and `create_file`. The coding agent must use these — not the underlying filesystem tools.

Every tool has the same seven INTENT parameters appended. All are required. Pydantic validates on arrival. Missing parameters = tool call fails before reaching the interceptor.

### Tool Signatures

```python
@mcp.tool()
async def vigil_write_file(
    path: str,
    content: str,
    intent: str,
    reason: str,
    affects: list[str],
    invariants_touched: list[str],
    assumes: list[str]
) -> str:
    """
    Write content to a file. Intercepts the write for security analysis before
    committing. Requires structured INTENT parameters — do not omit them.

    affects: list of security domains this write touches.
             Valid values: auth, crypto, logging, data-exposure,
             input-validation, file-system, network, none
    invariants_touched: list of invariant IDs from the Architecture Brief
                        being intentionally relaxed. Empty list if none.
    assumes: list of external guarantees being relied on, e.g.
             ["JWT middleware active on this route"]. Empty list if none.
    """
    ...

@mcp.tool()
async def vigil_str_replace(
    path: str,
    old_str: str,
    new_str: str,
    intent: str,
    reason: str,
    affects: list[str],
    invariants_touched: list[str],
    assumes: list[str]
) -> str:
    """
    Replace a string in a file. Intercepts the replacement for security
    analysis before committing. Requires structured INTENT parameters.
    """
    ...

@mcp.tool()
async def vigil_create_file(
    path: str,
    file_text: str,
    intent: str,
    reason: str,
    affects: list[str],
    invariants_touched: list[str],
    assumes: list[str]
) -> str:
    """
    Create a new file. Intercepts the creation for security analysis before
    committing. Requires structured INTENT parameters.
    """
    ...
```

The docstrings matter — they are included in the MCP tool manifest that the coding agent reads. Write them clearly so the agent understands what each INTENT parameter expects.

---

## `server/main.py` — MCP Server Entrypoint

This is the entry point. It:
1. Reads the user's project prompt from an env var or CLI arg
2. Calls the Architecture Brief generator
3. Initializes the session (logger, context manager, interceptor)
4. Registers the three tools
5. Starts the MCP server

```python
import asyncio
import os
import uuid
from mcp.server import Server
from mcp.server.stdio import stdio_server
from brief.generator import generate_brief
from server.interceptor import Interceptor
from audit.logger import AuditLogger
from server.context import ContextManager

mcp = Server("vigil")

# Global session state — initialized at startup
_interceptor: Interceptor | None = None

async def initialize_session(project_prompt: str) -> Interceptor:
    session_id = str(uuid.uuid4())[:8]
    print(f"[Vigil] Starting session {session_id}")

    # Phase 1: Generate Architecture Brief
    print("[Vigil] Generating Architecture Brief...")
    brief = await generate_brief(project_prompt)
    print(f"[Vigil] Brief generated. {len(brief.invariants)} invariants defined.")

    # Initialize logger and context
    logger = AuditLogger(session_id=session_id)
    logger.log_brief_generated(brief.raw_markdown)

    context = ContextManager(brief=brief)

    # Initialize interceptor (classifier + tiers wired in Phase 3/4)
    interceptor = Interceptor(
        brief=brief,
        context=context,
        logger=logger,
        session_id=session_id
    )

    return interceptor


@mcp.tool()
async def vigil_write_file(
    path: str,
    content: str,
    intent: str,
    reason: str,
    affects: list[str],
    invariants_touched: list[str],
    assumes: list[str]
) -> str:
    return await _interceptor.handle(
        tool="vigil_write_file",
        file_path=path,
        params={"path": path, "content": content},
        intent_raw={
            "intent": intent, "reason": reason,
            "affects": affects, "invariants_touched": invariants_touched,
            "assumes": assumes
        }
    )


@mcp.tool()
async def vigil_str_replace(
    path: str,
    old_str: str,
    new_str: str,
    intent: str,
    reason: str,
    affects: list[str],
    invariants_touched: list[str],
    assumes: list[str]
) -> str:
    return await _interceptor.handle(
        tool="vigil_str_replace",
        file_path=path,
        params={"path": path, "old_str": old_str, "new_str": new_str},
        intent_raw={
            "intent": intent, "reason": reason,
            "affects": affects, "invariants_touched": invariants_touched,
            "assumes": assumes
        }
    )


@mcp.tool()
async def vigil_create_file(
    path: str,
    file_text: str,
    intent: str,
    reason: str,
    affects: list[str],
    invariants_touched: list[str],
    assumes: list[str]
) -> str:
    return await _interceptor.handle(
        tool="vigil_create_file",
        file_path=path,
        params={"path": path, "file_text": file_text},
        intent_raw={
            "intent": intent, "reason": reason,
            "affects": affects, "invariants_touched": invariants_touched,
            "assumes": assumes
        }
    )


async def main():
    global _interceptor

    project_prompt = os.environ.get("VIGIL_PROJECT_PROMPT", "")
    if not project_prompt:
        raise ValueError("VIGIL_PROJECT_PROMPT env var must be set before starting Vigil.")

    _interceptor = await initialize_session(project_prompt)
    print("[Vigil] MCP server ready. Waiting for tool calls.")

    async with stdio_server() as (read_stream, write_stream):
        await mcp.run(read_stream, write_stream, mcp.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
```

---

## `server/interceptor.py` — Stub Interceptor

Phase 2 version. No classifier, no tiers yet. Just parses INTENT, extracts diff, logs the call, and returns APPROVE. This stub is replaced incrementally in Phases 3 and 4.

```python
from models.intent import IntentMessage
from models.verdict import Verdict, ToolCallResult
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief
from audit.logger import AuditLogger
from server.context import ContextManager
import json

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

    async def handle(
        self,
        tool: str,
        file_path: str,
        params: dict,
        intent_raw: dict
    ) -> str:
        call_id = self.context.next_call_id()

        # Parse INTENT — Pydantic validates, empty fields allowed
        intent = IntentMessage(**intent_raw)

        # Extract diff from tool params
        diff = self._extract_diff(tool, params)

        # --- Phase 3 will insert: classifier + Tier 1 here ---
        # --- Phase 4 will insert: pending_block injection + Tier 2 here ---

        # Stub: approve everything
        verdict = Verdict(verdict="APPROVE", finding=None)

        # Log and accumulate context
        entry = ContextEntry(
            call_id=call_id,
            tool=tool,
            file_path=file_path,
            diff=diff,
            intent=intent,
            verdict="APPROVE",
            full_verdict=verdict,
        )
        self.context.append(entry)
        self.logger.log_tool_call(entry)

        # Execute the actual file operation
        self._execute(tool, params)

        return self._format_response(ToolCallResult(allowed=True, verdict=verdict, message="[Vigil] APPROVE"))

    def _extract_diff(self, tool: str, params: dict) -> str:
        if tool == "vigil_write_file":
            return params.get("content", "")
        elif tool == "vigil_str_replace":
            removed = params.get("old_str", "")
            added = params.get("new_str", "")
            return f"REMOVED:\n{removed}\nADDED:\n{added}"
        elif tool == "vigil_create_file":
            return params.get("file_text", "")
        return ""

    def _execute(self, tool: str, params: dict):
        """Actually write the file to disk."""
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
```

---

## `server/context.py` — Context Manager

Manages the accumulating session context. Keeps the call counter. Phase 4 will add compression logic here.

```python
from models.context_entry import ContextEntry
from brief.schema import ArchitectureBrief

class ContextManager:
    def __init__(self, brief: ArchitectureBrief):
        self.brief = brief
        self.entries: list[ContextEntry] = []
        self._call_counter = 0

    def next_call_id(self) -> int:
        self._call_counter += 1
        return self._call_counter

    def append(self, entry: ContextEntry):
        self.entries.append(entry)

    def get_history(self) -> list[ContextEntry]:
        return list(self.entries)

    def malformed_intent_count(self) -> int:
        return sum(1 for e in self.entries if e.malformed_intent)

    def __len__(self):
        return len(self.entries)
```

---

## `brief/generator.py` — Architecture Brief Generator

Makes a single API call to a reasoning model with the brief generation prompt. Parses the markdown response into an `ArchitectureBrief` object.

```python
import anthropic
import os
from pathlib import Path
from brief.schema import ArchitectureBrief, SecurityInvariant, TrustBoundary
import re

_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

def _load_prompt() -> str:
    return Path("prompts/brief_generation.txt").read_text()

async def generate_brief(project_prompt: str) -> ArchitectureBrief:
    """
    Calls the reasoning model with the project prompt and parses the
    returned markdown into a structured ArchitectureBrief.
    """
    system_prompt = _load_prompt()

    response = _client.messages.create(
        model="claude-opus-4-5",   # reasoning model for Phase 1
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": project_prompt}]
    )

    raw_markdown = response.content[0].text
    return _parse_brief(raw_markdown)


def _parse_brief(markdown: str) -> ArchitectureBrief:
    """
    Parses the structured markdown brief into an ArchitectureBrief object.
    Uses simple section extraction — not regex soup. If parsing fails on a
    section, use a safe default and continue.
    """
    sections = _extract_sections(markdown)

    return ArchitectureBrief(
        system_purpose=sections.get("System Purpose", "").strip(),
        trust_boundaries=_parse_trust_boundaries(sections.get("Trust Boundaries", "")),
        auth_model=sections.get("Auth Model", "").strip(),
        data_flows=_parse_list(sections.get("Data Flows", "")),
        invariants=_parse_invariants(sections.get("Security Invariants", "")),
        sensitive_operations=_parse_list(sections.get("Sensitive Operations", "")),
        raw_markdown=markdown
    )


def _extract_sections(markdown: str) -> dict[str, str]:
    """Split markdown into section_name -> content dict."""
    sections = {}
    current_section = None
    current_lines = []

    for line in markdown.splitlines():
        if line.startswith("## "):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = line[3:].strip()
            current_lines = []
        elif current_section:
            current_lines.append(line)

    if current_section:
        sections[current_section] = "\n".join(current_lines).strip()

    return sections


def _parse_list(text: str) -> list[str]:
    return [
        line.lstrip("-•* ").strip()
        for line in text.splitlines()
        if line.strip() and line.strip().startswith(("-", "•", "*"))
    ]


def _parse_trust_boundaries(text: str) -> list[TrustBoundary]:
    boundaries = []
    for line in text.splitlines():
        line = line.strip().lstrip("-•* ").strip()
        if ":" in line:
            label, rest = line.split(":", 1)
            patterns = [p.strip() for p in rest.split(",") if p.strip()]
            boundaries.append(TrustBoundary(label=label.strip(), patterns=patterns))
    return boundaries


def _parse_invariants(text: str) -> list[SecurityInvariant]:
    invariants = []
    for line in text.splitlines():
        line = line.strip()
        # Matches: - [ ] id: description
        match = re.match(r"-\s*\[[ x]\]\s*([^:]+):\s*(.+)", line)
        if match:
            inv_id = match.group(1).strip()
            description = match.group(2).strip()
            invariants.append(SecurityInvariant(id=inv_id, description=description))
    return invariants
```

---

## Environment Setup

Create a `.env` file (gitignored):

```
ANTHROPIC_API_KEY=sk-ant-...
VIGIL_PROJECT_PROMPT="Building a payment processing microservice. JWT auth on all /api/v1/ routes. Admin panel at /admin/*. Payment data must never be logged. PostgreSQL backend."
```

Load it in `main.py` at the top:

```python
from dotenv import load_dotenv
load_dotenv()
```

---

## Running the Server

```bash
# Install deps
pip install -r requirements.txt

# Start Vigil MCP server
python -m server.main

# Or via MCP CLI (if using Claude Code)
VIGIL_PROJECT_PROMPT="your prompt here" python server/main.py
```

For Claude Code, add to `.mcp.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "python",
      "args": ["server/main.py"],
      "env": {
        "VIGIL_PROJECT_PROMPT": "your project description here",
        "ANTHROPIC_API_KEY": "your key here"
      }
    }
  }
}
```

---

## Tests to Write — `tests/test_phase2.py`

```python
import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock
from brief.schema import ArchitectureBrief
from brief.generator import _parse_brief
from server.context import ContextManager
from server.interceptor import Interceptor
from audit.logger import AuditLogger
from models.intent import IntentMessage

SAMPLE_BRIEF_MARKDOWN = """
# Architecture Brief

## System Purpose
Payment processing microservice.

## Trust Boundaries
- PUBLIC: /api/v1/checkout, /api/v1/products
- AUTHENTICATED: /api/v1/orders
- INTERNAL ONLY: /api/internal/*, /admin/*

## Auth Model
JWT-based. Middleware on /api/v1/ routes.

## Data Flows
- User input -> validation -> DB write
- Payment data -> never logged

## Security Invariants
- [ ] no-pii-in-logs: Payment data must never appear in log calls
- [ ] admin-role-required: /admin/* never reachable without role=admin

## Sensitive Operations
- DB writes
- External payment API calls
"""

def test_parse_brief_sections():
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    assert "Payment" in brief.system_purpose
    assert len(brief.trust_boundaries) == 3
    assert len(brief.invariants) == 2
    assert brief.invariants[0].id == "no-pii-in-logs"

def test_parse_brief_trust_boundaries():
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    public = next(b for b in brief.trust_boundaries if b.label == "PUBLIC")
    assert "/api/v1/checkout" in public.patterns

def test_context_manager_call_ids():
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    ctx = ContextManager(brief=brief)
    assert ctx.next_call_id() == 1
    assert ctx.next_call_id() == 2
    assert len(ctx) == 0  # entries only added on append

@pytest.mark.asyncio
async def test_interceptor_stub_approves(tmp_path):
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="test01", log_dir=str(tmp_path))
    interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="test01")

    result = await interceptor.handle(
        tool="vigil_create_file",
        file_path=str(tmp_path / "test.py"),
        params={"path": str(tmp_path / "test.py"), "file_text": "print('hello')"},
        intent_raw={
            "intent": "create hello script",
            "reason": "testing",
            "affects": [],
            "invariants_touched": [],
            "assumes": []
        }
    )
    assert "APPROVE" in result
    assert len(ctx) == 1

@pytest.mark.asyncio
async def test_interceptor_creates_file(tmp_path):
    brief = _parse_brief(SAMPLE_BRIEF_MARKDOWN)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="test02", log_dir=str(tmp_path))
    interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="test02")

    target = tmp_path / "output.py"
    await interceptor.handle(
        tool="vigil_create_file",
        file_path=str(target),
        params={"path": str(target), "file_text": "x = 1"},
        intent_raw={"intent": "x", "reason": "y", "affects": [], "invariants_touched": [], "assumes": []}
    )
    assert target.exists()
    assert target.read_text() == "x = 1"

def test_audit_log_written(tmp_path):
    logger = AuditLogger(session_id="test03", log_dir=str(tmp_path))
    log_file = tmp_path / "session_test03.jsonl"
    assert log_file.exists()
    lines = log_file.read_text().strip().splitlines()
    assert len(lines) == 1  # session_start event
    event = json.loads(lines[0])
    assert event["event"] == "session_start"
```

---

## Completion Criteria for Phase 2

- [ ] `pytest tests/test_phase2.py` passes fully
- [ ] MCP server starts without error: `python server/main.py`
- [ ] Architecture Brief is printed to stdout on startup (verify it parses correctly)
- [ ] All three `vigil_*` tools appear in the MCP tool manifest (test with `mcp dev server/main.py`)
- [ ] A coding agent (Claude Code) can connect and call `vigil_create_file` — gets `[Vigil] APPROVE` back
- [ ] File is actually written to disk after the tool call
- [ ] Audit log JSONL is written to `logs/session_<id>.jsonl`

## What Phase 3 Will Build On

Phase 3 wires the INTENT classifier and Tier 1 model into `interceptor.py`. The stub `# Phase 3 will insert` comment is the exact insertion point. Phase 3 never touches `main.py` or `brief/generator.py` — only `classifier.py`, `tier1.py`, and the relevant section of `interceptor.py`.
