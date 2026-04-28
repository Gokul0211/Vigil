# Vigil

A real-time security layer that sits between an AI coding agent and the file system. It intercepts every file write before it lands, analyzes the code against a session-specific architecture brief, and blocks vulnerabilities as they are introduced — not after.

---

## The Problem

Every existing security tool for AI-generated code runs after the fact. By the time a scanner sees the file, the coding agent's context is gone. It doesn't know what the code was supposed to do, what assumptions were made, or what was written three files ago that made this file dangerous. Static scanners catch `eval(input)`. They don't catch an auth bypass that only makes sense in context.

Vigil runs inside the session. It sees the same context the agent does.

---

## How It Works

Vigil is an MCP server. When a coding agent calls `vigil_write_file`, `vigil_str_replace`, or `vigil_create_file`, the write is intercepted before touching disk. Every tool call includes structured INTENT parameters — what the code does, what security domains it touches, what external guarantees it relies on. These are required fields in the tool schema, not optional prose.

**Session start — Architecture Brief generation**

Before any code is written, Vigil calls a reasoning model with the project description and produces a structured Architecture Brief: trust boundaries, auth model, data flows, and a list of security invariants that must always hold. This brief is the ground truth for every security decision in the session.

**Per tool call — two-tier analysis**

Every intercepted write goes through a two-tier pipeline:

The INTENT classifier runs first, in Python, with no model call. If the diff contains no sensitive patterns and the agent declared no security-relevant domains, the call is skipped. This eliminates roughly 60-70% of calls before any model sees them.

Tier 1 is a fast model (Haiku) running synchronously. It handles high-confidence cases only: hardcoded secrets, unsanitized input in SQL queries, PII written to logs. If it's certain, it returns `CLEAR_BLOCK` and the file is not written. If it's unsure, it returns `AMBIGUOUS`.

Tier 2 is a frontier model (Opus) running asynchronously. It handles `AMBIGUOUS` cases and has the full session context: the Architecture Brief, every prior diff, every prior INTENT, and every prior verdict. This is where business logic flaws and architectural drift get caught — things that only make sense across multiple files. The tool call that triggered Tier 2 is allowed through while analysis runs in the background. If Tier 2 finds a violation, the finding is stored and injected at the next tool call boundary.

---

## Smoke Test Results

These results are from a live session using Groq (Llama 3.1 8B for Tier 1, Llama 3.3 70B for Tier 2) against a payment processing project brief with four deliberate vulnerabilities introduced.

```
# Vigil Session Report — smoke

## Summary
| Metric              | Count |
|---------------------|-------|
| Total tool calls    | 5     |
| Blocked             | 3     |
| Ambiguous (Tier 2)  | 1     |
| Skipped             | 1     |

## Security Findings

### Call #1 — CLEAR_BLOCK (CRITICAL)
File: src/config.py
Finding: Hardcoded Stripe secret in source
Fix: Move secret to environment variables
Invariant violated: no-hardcoded-secrets

### Call #3 — CLEAR_BLOCK (HIGH)
File: src/payment.py
Finding: Payment data written to log
Fix: Remove card number from log call
Invariant violated: no-pii-in-logs

### Call #2 — BLOCK (CRITICAL) [Tier 2, async]
File: src/db.py
Finding: SQL injection — uid parameter passed directly into query string without sanitization
Fix: Use parameterized query: db.execute("SELECT * FROM users WHERE id = ?", (uid,))
Invariant violated: no-pii-in-logs

## Invariant Violations
- no-hardcoded-secrets
- no-pii-in-logs
```

Call #4 (a pure math utility function) was correctly skipped — no model was called.

Call #2 is the interesting one. Tier 1 returned `AMBIGUOUS` on the SQL injection because it wanted more context. Tier 2 caught it in the background and injected the block at the next tool call. The file was written but the agent was halted before it could continue.

---

## Setup

**Install**

```bash
pip install -r requirements.txt
```

**Configure**

```bash
cp .env.example .env
```

Edit `.env` and set:
- `ANTHROPIC_API_KEY` — your Anthropic API key
- `VIGIL_PROJECT_PROMPT` — a description of the project you're building

**Add to Claude Code**

In your project root, create or edit `.mcp.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "python",
      "args": ["<path_to_vigil>/server/main.py"],
      "env": {
        "VIGIL_PROJECT_PROMPT": "your project description here",
        "ANTHROPIC_API_KEY": "your key here"
      }
    }
  }
}
```

Copy `CLAUDE.md` into your project root. Claude Code reads it before every session and learns to use `vigil_*` tools for all file writes.

---

## Smoke Test

To validate the pipeline without a full Claude Code session:

```bash
python smoke_test.py
```

This runs five test writes directly against the interceptor — a hardcoded secret, a SQL injection, PII in a log call, a clean utility function, and a write with an unverified external assumption. Then inspect the results:

```bash
python vigil_cli.py report smoke
```

---

## CLI

```bash
python vigil_cli.py list                     # all sessions with block counts
python vigil_cli.py report <session_id>      # full markdown report
python vigil_cli.py findings <session_id>    # only BLOCK findings
python vigil_cli.py stats <session_id>       # verdict breakdown
```

---

## Tests

```bash
pytest                         # full suite (42 tests)
pytest tests/test_models.py    # schemas only
pytest tests/test_phase3.py    # classifier + Tier 1
pytest tests/test_phase4.py    # Tier 2 + pending_block injection
pytest tests/test_e2e.py       # end-to-end pipeline scenarios
```

---

## Design Decisions

**Why intercept at the MCP layer rather than post-commit**

The agent's context disappears after the session. A post-hoc scanner sees the file but not why it was written, what assumptions were made, or what was written in other files that make this one dangerous. Interception at write time is the only point where full context is available.

**Why INTENT as required tool parameters, not free-form text**

An earlier design asked the agent to emit a structured `INTENT` block before each write as prose. That's a soft dependency — the agent can forget, rush, or write garbage. Making INTENT fields required parameters in the tool schema means a missing field fails schema validation before the interceptor sees anything. The agent can still pass empty values, so the classifier also infers security relevance from the diff directly as a fallback.

**Why two tiers instead of one**

A single model running synchronously on every write is too slow and too expensive. Most writes are not security-relevant. The classifier eliminates the majority of calls before any model runs. Tier 1 handles clear-cut cases fast. Tier 2 only runs when needed, and runs async so it doesn't block the agent. The tradeoff is that Tier 2 findings are deferred by one tool call — an acceptable cost given that the finding still interrupts the session before more code is written.

**Why fail-open**

If Tier 1 fails (network error, timeout, quota), it returns `AMBIGUOUS` rather than blocking. If Tier 2 fails, it returns `APPROVE`. A security tool that bricks a coding session on an upstream outage will get disabled. Fail-open on errors, with the audit log recording every failure, is the right default for a developer tool.

---

## Roadmap

**ASSUMES verification** — every `assumes` field across the session is recorded but not verified. A post-session pass that cross-checks each assumption against what was actually written is the most valuable next feature. If an agent writes `assumes: ["JWT middleware active on this route"]` but no middleware was ever written, that's worth flagging.

**Interactive brief review** — the Architecture Brief is generated from the project prompt without human review. Letting the user edit invariants before the session starts would improve catch quality significantly. Brief quality is the main variable in Tier 2 accuracy.

**Override mechanism** — let the user confirm a BLOCK and proceed with a required justification. Log the override with full context. Currently a block is a hard stop.

**Fine-tuning dataset collection** — every `AMBIGUOUS -> BLOCK` or `AMBIGUOUS -> APPROVE` pair from Tier 2 is a labeled training example. Collecting these across sessions would eventually allow fine-tuning Tier 1 on real cases from your own codebase.

**Severity thresholds** — configure minimum severity for blocking vs warning. `CRITICAL` always blocks. `LOW` produces a warning but allows the write.
