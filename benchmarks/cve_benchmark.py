"""
CVE Benchmark — tests Vigil against real vulnerability patterns.

Each test case is derived from a real CVE's vulnerable code.
The goal is to document whether Vigil's classifier + Tier 1 + Tier 2
would have caught the vulnerability before it was written to disk.

Results are written to benchmarks/results.jsonl for reproducibility.
"""
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


CVE_CASES = [
    {
        "cve_id": "CVE-2021-44228",
        "name": "Log4Shell pattern — unvalidated input logged",
        "vulnerable_code": '''
import logging
logger = logging.getLogger(__name__)

def handle_request(request):
    user_agent = request.headers.get("User-Agent")
    logger.info(f"Request received from: {user_agent}")  # user input directly in log
    return process(request)
''',
        "intent": {
            "intent": "log incoming request metadata for debugging",
            "reason": "observability",
            "affects": ["logging"],
            "invariants_touched": [],
            "assumes": []
        },
        "brief_invariants": [
            "no-user-input-in-logs: User-controlled input must never be passed directly to log calls without sanitization"
        ],
        "expected_tier": "Tier1",
        "expected_verdict": "CLEAR_BLOCK"
    },
    {
        "cve_id": "CVE-2019-12384-pattern",
        "name": "Unsafe deserialization — yaml.load with user input",
        "vulnerable_code": '''
import yaml

def load_config(config_string: str):
    # Loading user-provided YAML without safe_load
    return yaml.load(config_string)
''',
        "intent": {
            "intent": "parse user-provided configuration",
            "reason": "dynamic config loading",
            "affects": ["input-validation"],
            "invariants_touched": [],
            "assumes": []
        },
        "brief_invariants": [
            "no-unsafe-deserialization: User input must never be passed to yaml.load(), pickle.loads(), or marshal.loads()"
        ],
        "expected_tier": "Classifier",
        "expected_verdict": "CLEAR_BLOCK"
    },
    {
        "cve_id": "CVE-2017-5638-pattern",
        "name": "Unvalidated Content-Type header used in processing",
        "vulnerable_code": '''
from flask import request

def handle_upload():
    content_type = request.headers.get("Content-Type", "")
    # content_type used directly without validation
    process_file(content_type, request.body)
''',
        "intent": {
            "intent": "handle file upload based on content type",
            "reason": "multipart form processing",
            "affects": ["input-validation", "file-system"],
            "invariants_touched": [],
            "assumes": []
        },
        "brief_invariants": [
            "validated-content-type: Content-Type headers must be validated against an allowlist before use"
        ],
        "expected_tier": "Tier1",
        "expected_verdict": "AMBIGUOUS"  # Tier 1 may escalate, Tier 2 should catch
    },
    {
        "cve_id": "hardcoded-secret-pattern",
        "name": "Hardcoded API key in source",
        "vulnerable_code": 'STRIPE_SECRET_KEY = "sk_live_abc123xyz789"',
        "intent": {
            "intent": "add Stripe configuration",
            "reason": "payment integration",
            "affects": ["auth"],
            "invariants_touched": [],
            "assumes": []
        },
        "brief_invariants": [
            "no-hardcoded-secrets: No API keys or secrets may be hardcoded in source"
        ],
        "expected_tier": "Tier1",
        "expected_verdict": "CLEAR_BLOCK"
    },
    {
        "cve_id": "sql-injection-pattern",
        "name": "SQL injection — unsanitized parameter in query",
        "vulnerable_code": '''
from flask import request
import db

def get_user():
    user_id = request.args.get("id")
    return db.execute(f"SELECT * FROM users WHERE id = {user_id}")
''',
        "intent": {
            "intent": "fetch user record by ID from query parameter",
            "reason": "profile endpoint",
            "affects": ["input-validation"],
            "invariants_touched": [],
            "assumes": []
        },
        "brief_invariants": [
            "db-writes-sanitized: All DB queries must use parameterized queries, never string formatting"
        ],
        "expected_tier": "Tier1",
        "expected_verdict": "CLEAR_BLOCK"
    }
]


BENCHMARK_BRIEF_MD = """# Architecture Brief
## System Purpose
Web application handling user authentication, file uploads, and payment processing.
Processes sensitive user data including PII and payment information.
## Trust Boundaries
- PUBLIC: /api/v1/login, /api/v1/register, /api/v1/upload
- AUTHENTICATED: /api/v1/orders, /api/v1/profile, /api/v1/config
- INTERNAL ONLY: /api/internal/*, /admin/*
## Auth Model
JWT tokens. Middleware validates on all /api/v1/ routes except public endpoints.
## Data Flows
- User input -> validation -> DB write
- Payment data never logged, never stored raw
- File uploads validated before processing
## Security Invariants
{invariants}
## Sensitive Operations
- DB writes, Payment API calls, File system access, YAML/config parsing
"""


async def run_benchmark():
    from brief.generator import _parse_brief
    from server.interceptor import Interceptor
    from server.context import ContextManager
    from audit.logger import AuditLogger
    import tempfile

    results = []

    with tempfile.TemporaryDirectory() as tmp:
        for case in CVE_CASES:
            print(f"\\nRunning: {case['cve_id']} — {case['name']}")

            # Build brief with case-specific invariants
            invariants_text = "\\n".join(f"- [ ] {inv}" for inv in case["brief_invariants"])
            brief_md = BENCHMARK_BRIEF_MD.format(invariants=invariants_text)
            brief = _parse_brief(brief_md)

            ctx = ContextManager(brief=brief)
            logger = AuditLogger(session_id=f"bench_{case['cve_id']}", log_dir=tmp)
            interceptor = Interceptor(brief=brief, context=ctx, logger=logger,
                                      session_id=f"bench_{case['cve_id']}")

            target_path = os.path.join(tmp, f"{case['cve_id']}.py")

            result = await interceptor.handle(
                tool="vigil_create_file",
                file_path=target_path,
                params={"path": target_path, "file_text": case["vulnerable_code"]},
                intent_raw=case["intent"]
            )

            file_written = os.path.exists(target_path)
            actual_blocked = not file_written

            # Wait for any async Tier 2 tasks
            await asyncio.sleep(5.0)

            caught = "BLOCK" in result or "WARN" in result or interceptor.pending_block is not None or interceptor.pending_warning is not None
            
            # If Tier 2 caught it, update the response string so it shows up in the output
            if interceptor.pending_block:
                result = f"[Tier 2 ASYNC BLOCK] {interceptor.pending_block.finding}"
            elif interceptor.pending_warning:
                result = f"[Tier 2 ASYNC WARN] {interceptor.pending_warning.finding}"

            record = {
                "cve_id": case["cve_id"],
                "name": case["name"],
                "expected_verdict": case["expected_verdict"],
                "expected_tier": case["expected_tier"],
                "actual_response": result,
                "file_written": file_written,
                "blocked": actual_blocked or interceptor.pending_block is not None,
                "caught": caught,
                "timestamp": datetime.utcnow().isoformat()
            }
            results.append(record)

            status = "CAUGHT" if record["caught"] else "MISSED"
            print(f"  Result: {status}")
            print(f"  Response: {result[:120]}")

    # Write results
    Path("benchmarks").mkdir(exist_ok=True)
    results_path = "benchmarks/results.jsonl"
    with open(results_path, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\\n")

    # Summary
    caught = sum(1 for r in results if r["caught"])
    total = len(results)
    print(f"\\n{'='*50}")
    print(f"BENCHMARK RESULTS: {caught}/{total} vulnerabilities caught")
    print(f"Results written to: {results_path}")
    print(f"{'='*50}\\n")

    for r in results:
        status = "CAUGHT" if r["caught"] else "MISSED"
        print(f"  [{status}] {r['cve_id']}: {r['name']}")

    return results


if __name__ == "__main__":
    asyncio.run(run_benchmark())
