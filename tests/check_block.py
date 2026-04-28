import asyncio, sys, os
sys.path.insert(0, ".")
os.environ.setdefault("ANTHROPIC_API_KEY", "dummy")

from unittest.mock import patch
from models.verdict import Verdict


async def test():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        from brief.generator import _parse_brief
        from server.interceptor import Interceptor
        from server.context import ContextManager
        from audit.logger import AuditLogger

        brief = _parse_brief(
            "# Architecture Brief\n## System Purpose\nTest.\n## Trust Boundaries\n"
            "- PUBLIC: /api/*\n## Auth Model\nJWT.\n## Data Flows\n- x\n"
            "## Security Invariants\n## Sensitive Operations\n"
        )
        ctx = ContextManager(brief=brief)
        logger = AuditLogger(session_id="chk", log_dir=tmp)
        interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="chk")
        target = os.path.join(tmp, "secret.py")

        with patch("server.interceptor.analyze_sync",
                   return_value=Verdict(verdict="CLEAR_BLOCK", severity="CRITICAL",
                                        finding="hardcoded secret", fix="use env var")):
            result = await interceptor.handle(
                tool="vigil_create_file",
                file_path=target,
                params={"path": target, "file_text": "API_KEY=sk-123"},
                intent_raw={"intent": "x", "reason": "y", "affects": ["auth"],
                             "invariants_touched": [], "assumes": []}
            )

        assert not os.path.exists(target), "FAIL: file was written on CLEAR_BLOCK"
        assert "BLOCK" in result, f"FAIL: response did not contain BLOCK: {result}"
        print("PASS: CLEAR_BLOCK correctly prevented file write")


asyncio.run(test())
