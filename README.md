# Vigil

> A real-time security watcher for AI coding agents.

Vigil is a co-resident, context-aware security layer that intercepts AI-generated code at the MCP layer, understands architectural intent, and catches vulnerabilities and business logic flaws as they are introduced — not after.

## Quick Start

### 1. Install
pip install -r requirements.txt

### 2. Configure
cp .env.example .env
# Edit .env — set ANTHROPIC_API_KEY and VIGIL_PROJECT_PROMPT

### 3. Add to Claude Code
Add to .mcp.json in your project root:
{
  "mcpServers": {
    "vigil": {
      "command": "python",
      "args": ["<path_to_vigil>/server/main.py"],
      "env": {
        "VIGIL_PROJECT_PROMPT": "your project description",
        "ANTHROPIC_API_KEY": "your key"
      }
    }
  }
}

Copy CLAUDE.md template into your project root.

### 4. Start Coding
Claude Code will automatically use vigil_* tools for all file writes.

---

## Results

Here is an example audit report generated from `smoke_test.py`, demonstrating the pipeline catching a hardcoded secret at Tier 1, and catching a SQL injection vulnerability via asynchronous deep analysis at Tier 2.

```markdown
# Vigil Session Report — smoke

**Started:** 2026-04-28T13:49:50.012889

## Summary
| Metric | Count |
|---|---|
| Total tool calls | 6 |
| Approved | 1 |
| Blocked | 3 |
| Ambiguous (Tier 2 routed) | 1 |
| Skipped (not security relevant) | 1 |
| Malformed INTENT (inferred) | 1 |

## Security Findings

### Call #1 — CLEAR_BLOCK (CRITICAL)
**File:** `src/config.py`
**Tool:** vigil_create_file
**Intent:** add stripe config
**Finding:** Hardcoded stripe secret in source
**Fix:** Move secret to environment variables or a secure secret storage
**Invariant violated:** `no-hardcoded-secrets`
**Timestamp:** 2026-04-28T13:49:50.519801

### Call #3 — CLEAR_BLOCK (HIGH)
**File:** `src/payment.py`
**Tool:** vigil_create_file
**Intent:** process payment
**Finding:** Payment data written to log.
**Fix:** Move payment data processing out of the logging function, or configure the logger to not output sensitive data.
**Invariant violated:** `no-pii-in-logs`
**Timestamp:** 2026-04-28T13:49:50.957388

### Call #2 — BLOCK (CRITICAL)
**File:** `[async]`
**Tool:** tier2_async_result
**Intent:** fetch user from db
**Finding:** The current code diff introduces a SQL injection vulnerability in the `get_user` function. The `uid` parameter is not sanitized, allowing an attacker to inject malicious SQL code.
**Fix:** Use a parameterized query or an ORM to prevent SQL injection. For example, `db.execute("SELECT * FROM users WHERE id = ?", (uid,))`
**Invariant violated:** `no-pii-in-logs`
**Timestamp:** 2026-04-28T13:49:52.180536

## Malformed INTENT Signals

These calls had empty or garbage INTENT fields. Security relevance was inferred from the diff.

- Call #4: `src/utils.py` — affects empty or malformed; inferred from diff

## Invariant Violations
- ❌ `no-hardcoded-secrets`
- ❌ `no-pii-in-logs`
```

---

python vigil_cli.py list                    # List all sessions
python vigil_cli.py report <session_id>     # Full markdown report
python vigil_cli.py findings <session_id>   # Only BLOCK findings
python vigil_cli.py stats <session_id>      # Summary stats
python vigil_cli.py warns <session_id>      # WARN findings (below block threshold)
python vigil_cli.py export-dataset <session_id> [--negatives]  # Export fine-tuning pairs
python vigil_cli.py verify <session_id> [project_root]       # ASSUMES verification
python vigil_cli.py check-brief "prompt text"                # Validate brief quality

---

## How It Works

Every intercepted write passes through a two-tier pipeline. The INTENT classifier runs first in Python with no model call. Tier 1 (fast, sync) handles clear-cut cases — hardcoded secrets, SQL injection, PII in logs. Tier 2 (frontier, async) handles ambiguous cases with full session context for cross-file reasoning. Severity thresholds control whether findings block or warn.

**Post-session — ASSUMES verification**

At session end, `vigil_cli.py verify <session_id>` cross-checks every `assumes` field recorded during the session against what was actually written. If an agent wrote `assumes: ["JWT middleware active on /api/v1/ routes"]` but no middleware implementation exists in the codebase, the assumption is flagged as UNVERIFIED. Semantic pattern matching handles the obvious cases, and only ambiguous Codebase assumptions reach the LLM. Infrastructure assumptions (e.g. "VPC", "WAF") are automatically detected and flagged for manual review.

---

## Empirical Validation (CVE Benchmark)

Vigil is tested against 5 historical vulnerability patterns derived from real CVEs — Log4Shell, unsafe YAML deserialization, Struts Content-Type injection, hardcoded secrets, and SQL injection. Benchmarks run the full interceptor pipeline against real Groq model calls.

| CVE Pattern | Result | Tier |
|---|---|---|
| CVE-2021-44228 (Log4Shell — unvalidated input logged) | ✅ CAUGHT | Tier 2 async |
| CVE-2019-12384 (unsafe `yaml.load()`) | ✅ CAUGHT | Tier 1 sync |
| CVE-2017-5638 (unvalidated Content-Type) | ✅ CAUGHT | Tier 2 async |
| Hardcoded API key | ✅ CAUGHT | Tier 1 sync |
| SQL injection via f-string | ✅ CAUGHT | Tier 2 async |

**5/5 vulnerability class patterns caught** against synthetic code derived from real CVE patterns.
These are not runs against the original vulnerable libraries — they test whether Vigil catches
the underlying vulnerability class (unvalidated input in logs, unsafe deserialization, SQL injection,
hardcoded secrets). Full methodology and per-case records in [`benchmarks/README.md`](benchmarks/README.md).

**Advanced benchmark: 6/6 caught** including 5 cases requiring cross-context reasoning that grep-based scanners cannot detect. See [`benchmarks/README.md`](benchmarks/README.md).

## Running Tests

pytest                        # All 85 tests
pytest tests/test_models.py   # Phase 1: schemas only
pytest tests/test_phase2.py   # Phase 2: MCP server + brief gen
pytest tests/test_phase3.py   # Phase 3: classifier + Tier 1
pytest tests/test_phase4.py   # Phase 4: Tier 2 + pending_block
pytest tests/test_e2e.py      # Phase 5: full pipeline scenarios
pytest tests/test_phase6.py   # Phase 6: invariant validation, severity, dataset export
pytest tests/test_phase7.py   # Phase 7: ASSUMES verifier
pytest tests/test_phase8.py   # Phase 8: Hardening & CVE Benchmarks

---

## Project Status

- **Phase 1** — Project scaffold & data models ✅
- **Phase 2** — MCP server + tool definitions + brief generator ✅
- **Phase 3** — INTENT classifier + Tier 1 fast model ✅
- **Phase 4** — Tier 2 frontier model + context manager ✅
- **Phase 5** — Audit report, CLI, and end-to-end testing ✅
- **Phase 6** — Invariant grounding, severity thresholds, WARN state, dataset export ✅
- **Phase 7** — ASSUMES verification crawler ✅
- **Phase 8** — Architecture hardening, dataset robustness, and CVE benchmarking ✅

## Roadmap (Post V1)

1. **Interactive brief review** — before the session starts, show the generated brief and let the user edit invariants before any coding begins. Brief quality is the critical variable.
2. **Structured invariant tracking** — instead of invariant IDs as free strings, link them to `SecurityInvariant` objects. Track satisfied/violated state per session. Show a live invariant dashboard.
3. **Override mechanism** — let the user confirm a BLOCK and proceed anyway (with a required justification). Log the override with full context. Useful for deliberate invariant relaxation.
4. **Benchmarking** — run Vigil against historical CVEs in open-source projects to measure real-world catch rate and false positive rate.

---

*Vigil V2 — 85 tests across 8 phases.*
