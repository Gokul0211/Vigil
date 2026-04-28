import asyncio
import os
import uuid
from mcp.server.fastmcp import FastMCP
from brief.generator import generate_brief
from server.interceptor import Interceptor
from audit.logger import AuditLogger
from server.context import ContextManager
from dotenv import load_dotenv

load_dotenv()

mcp = FastMCP("vigil")

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
    """
    Replace a string in a file. Intercepts the replacement for security
    analysis before committing. Requires structured INTENT parameters.
    """
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
    """
    Create a new file. Intercepts the creation for security analysis before
    committing. Requires structured INTENT parameters.
    """
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

    await mcp.run_stdio_async()


if __name__ == "__main__":
    asyncio.run(main())
