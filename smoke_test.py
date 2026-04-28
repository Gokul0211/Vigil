import asyncio
import os
from dotenv import load_dotenv
load_dotenv()

# Directly call the interceptor as if you were a coding agent
from brief.generator import _parse_brief
from server.interceptor import Interceptor
from server.context import ContextManager
from audit.logger import AuditLogger

BRIEF_MD = """# Architecture Brief
## System Purpose
Simple web API for user authentication and payment processing.
## Trust Boundaries
- PUBLIC: /api/v1/login, /api/v1/register
- AUTHENTICATED: /api/v1/orders, /api/v1/profile
- INTERNAL ONLY: /api/internal/*, /admin/*
## Auth Model
JWT tokens. Middleware validates on all /api/v1/ routes.
## Data Flows
- User credentials -> validation -> DB lookup
- Payment data never logged, never stored raw
## Security Invariants
- [ ] no-hardcoded-secrets: No secrets or API keys hardcoded in source
- [ ] no-pii-in-logs: Payment and PII data must never appear in logs
- [ ] admin-role-required: /admin/* requires role=admin claim
## Sensitive Operations
- DB writes, JWT generation, Payment API calls
"""

async def main():
    brief = _parse_brief(BRIEF_MD)
    ctx = ContextManager(brief=brief)
    logger = AuditLogger(session_id="smoke", log_dir="logs")
    interceptor = Interceptor(brief=brief, context=ctx, logger=logger, session_id="smoke")

    print("\n--- Test 1: Hardcoded secret ---")
    result = await interceptor.handle(
        tool="vigil_create_file",
        file_path="src/config.py",
        params={"path": "src/config.py", "file_text": 'STRIPE_SECRET = "sk-prod-abc123xyz"'},
        intent_raw={"intent": "add stripe config", "reason": "payment integration", "affects": ["auth"], "invariants_touched": [], "assumes": []}
    )
    print(result)

    print("\n--- Test 2: SQL injection ---")
    result = await interceptor.handle(
        tool="vigil_create_file",
        file_path="src/db.py",
        params={"path": "src/db.py", "file_text": 'def get_user(uid):\n    return db.execute(f"SELECT * FROM users WHERE id = {uid}")'},
        intent_raw={"intent": "fetch user from db", "reason": "profile endpoint", "affects": ["input-validation"], "invariants_touched": [], "assumes": []}
    )
    print(result)

    print("\n--- Test 3: PII in logs ---")
    result = await interceptor.handle(
        tool="vigil_create_file",
        file_path="src/payment.py",
        params={"path": "src/payment.py", "file_text": 'def process(card_number):\n    logger.info(f"Processing card: {card_number}")'},
        intent_raw={"intent": "process payment", "reason": "checkout flow", "affects": ["logging", "data-exposure"], "invariants_touched": [], "assumes": []}
    )
    print(result)

    print("\n--- Test 4: Clean utility code (should SKIP) ---")
    result = await interceptor.handle(
        tool="vigil_create_file",
        file_path="src/utils.py",
        params={"path": "src/utils.py", "file_text": "def clamp(v, lo, hi):\n    return max(lo, min(hi, v))"},
        intent_raw={"intent": "add clamp utility", "reason": "math helper", "affects": [], "invariants_touched": [], "assumes": []}
    )
    print(result)

    print("\n--- Test 5: Unverified ASSUMES (should hit Tier 2) ---")
    result = await interceptor.handle(
        tool="vigil_create_file",
        file_path="src/internal.py",
        params={"path": "src/internal.py", "file_text": 'def admin_delete(user_id):\n    db.delete("users", user_id)'},
        intent_raw={"intent": "admin delete endpoint", "reason": "account management", "affects": ["auth"], "invariants_touched": [], "assumes": ["VPC enforces admin-only access", "role check done at gateway"]}
    )
    print(result)

    print("\n\nDone. Check logs/session_smoke.jsonl for the full audit trail.")
    print("Run: python vigil_cli.py report smoke")

    # Give Tier 2 background task a moment to finish before script exits
    await asyncio.sleep(5)

asyncio.run(main())
