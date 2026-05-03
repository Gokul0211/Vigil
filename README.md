# Vigil

A real-time security layer for AI coding agents. It sits between Claude Code and the file system, intercepts every write before it lands on disk, and catches vulnerabilities as they are introduced — not after.

---

## Why This Exists

AI coding agents write a lot of code fast. That's the point. But speed creates a problem: the agent's reasoning about why it wrote something is ephemeral. By the time a static scanner runs, the session is over, the context is gone, and you're left with a diff and no explanation.

Every existing security tool for AI-generated code is post-hoc. Semgrep, CodeQL, Snyk — they all run after the file is written, after the commit lands. They see the output but not the intent. They can pattern-match `eval(input)`. They cannot tell you that the agent wrote an admin endpoint without an auth check because it assumed the gateway would handle it — and the gateway was never built.

Vigil runs inside the session. It intercepts at the MCP tool call layer, which is the only point where three things exist simultaneously: what the agent intended to write, why it made that decision, and the actual code. Five seconds later the agent has moved on and that context is gone.

---

## How It Works

### Session Start — Architecture Brief

Before any code is written, Vigil calls a reasoning model with the project description and generates a structured Architecture Brief: trust boundaries, auth model, data flows, and a set of security invariants that must always hold. Something like:

```
no-pii-in-logs: Payment data must never appear in any log call
admin-role-required: /admin/* never reachable without role=admin claim
no-hardcoded-secrets: No API keys or credentials hardcoded in source
```

This brief is the ground truth for every security decision in the session. Tier 2 reasons against it. The ASSUMES verifier checks against it. Brief quality is the single biggest variable in Tier 2 accuracy — a vague prompt produces vague invariants.

Validate brief quality before starting:

```bash
python vigil_cli.py check-brief "your project description"
```

### Per Write — Two-Tier Pipeline

Every file write goes through a structured pipeline before touching disk.

**INTENT Classifier** runs first, in Python, with no model call. The agent passes structured INTENT parameters with every write — what the code does, what security domains it touches, what external guarantees it relies on. These are required fields in the tool schema, not optional prose the agent might forget. If `affects` is empty and the diff contains no sensitive patterns, the write is skipped entirely. This eliminates roughly 60-70% of calls before any model sees them. When the agent passes empty or garbage values, the classifier infers security relevance from the diff directly as a fallback.

**Tier 1** is a fast model (Haiku) running synchronously. It handles high-confidence cases only: hardcoded secrets, unsanitized input in SQL queries, PII written to logs. If it's certain, it returns `CLEAR_BLOCK` and the file is not written. If it's unsure, it returns `AMBIGUOUS`. The constraint is deliberate — Tier 1 must never block on speculation. On any model failure, it returns `AMBIGUOUS` rather than blocking, so a quota error or timeout never breaks your session.

**Tier 2** is a frontier model (Opus) running asynchronously. It handles `AMBIGUOUS` cases and has full session context: the Architecture Brief, every prior diff, every prior INTENT, every prior verdict. This is where business logic flaws get caught — things that only make sense across multiple files, or where the agent claimed one thing and wrote another. The write that triggered Tier 2 is allowed through while analysis runs in the background. If Tier 2 finds a violation, the finding is stored as `pending_block` and injected at the next tool call boundary, halting the session before more code builds on the vulnerability.

```
Tool call received
       │
       ▼
 INTENT Classifier ──► SKIP (60-70% of calls, no model)
       │
       ▼ (security relevant)
    Tier 1 ──────────► CLEAR_BLOCK (file NOT written, immediate)
       │
       ▼ AMBIGUOUS
  File written
       │
       ▼
  Tier 2 (async) ─────► APPROVE (session continues)
                    └──► pending_block (injected at next write)
```

### Post-Session — ASSUMES Verification

Every `assumes` field recorded during the session is cross-checked against the codebase after coding ends. If an agent wrote `assumes: ["JWT middleware active on all /api/v1/ routes"]` but no middleware was ever implemented, that assumption is flagged as UNVERIFIED.

The verifier uses a scoped approach: keyword-to-directory mapping narrows the search, static pattern detection handles obvious cases without any model call, and LLM reasoning only runs when relevant code exists but intent is unclear. Infrastructure assumptions (`VPC enforces this`, `AWS Gateway handles rate limiting`) are detected separately and flagged for manual review — they can't be verified by scanning Python source files.

```bash
python vigil_cli.py verify <session_id>
```

---

## Setup

### Install

```bash
git clone https://github.com/Gokul0211/vigil
cd vigil
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
```

Edit `.env`:

```
ANTHROPIC_API_KEY=sk-ant-...

# Be specific. Vague descriptions produce vague invariants and weaker Tier 2 reasoning.
VIGIL_PROJECT_PROMPT="Payment processing microservice. JWT auth on all /api/v1/ routes.
Admin panel at /admin/* requires role=admin claim. Card data must never be logged.
PostgreSQL backend. External Stripe API for payments."

# Optional: minimum severity to trigger a BLOCK. Below this becomes WARN (logged but not blocking).
# Values: LOW (default, everything blocks), MEDIUM, HIGH, CRITICAL
VIGIL_MIN_BLOCK_SEVERITY=LOW
```

### Connect to Claude Code

In your project root, create `.mcp.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "python",
      "args": ["/absolute/path/to/vigil/server/main.py"],
      "env": {
        "VIGIL_PROJECT_PROMPT": "your project description",
        "ANTHROPIC_API_KEY": "your key"
      }
    }
  }
}
```

Copy `CLAUDE.md` from the Vigil directory into your project root. Claude Code reads it at session start and uses `vigil_write_file`, `vigil_str_replace`, and `vigil_create_file` for all file operations instead of the standard tools.

### Smoke Test

Validates the pipeline without a full Claude Code session:

```bash
python smoke_test.py
python vigil_cli.py report smoke
```

---

## CLI Reference

```bash
python vigil_cli.py list                                        # all sessions with block counts
python vigil_cli.py report <session_id>                         # full markdown audit report
python vigil_cli.py findings <session_id>                       # only BLOCK/CLEAR_BLOCK entries
python vigil_cli.py stats <session_id>                          # verdict breakdown table
python vigil_cli.py warns <session_id>                          # findings below block threshold
python vigil_cli.py verify <session_id> [project_root]          # ASSUMES verification pass
python vigil_cli.py export-dataset <session_id> [--negatives]   # export fine-tuning JSONL
python vigil_cli.py check-brief "prompt text"                   # validate brief quality
```

---

## Empirical Validation

### CVE Benchmark

Five vulnerability class patterns derived from real CVEs. These are not runs against the original vulnerable libraries — they test whether Vigil catches the underlying vulnerability class in representative Python code. All runs use the full interceptor pipeline with real model calls (Llama 3.1 8B for Tier 1, Llama 3.3 70B for Tier 2 via Groq).

| CVE | Vulnerability Class | Result | Tier |
|---|---|---|---|
| CVE-2021-44228 (Log4Shell) | Unvalidated user input passed to logger | CAUGHT | Tier 2 async |
| CVE-2019-12384 | Unsafe `yaml.load()` with user input | CAUGHT | Tier 1 sync |
| CVE-2017-5638 (Apache Struts) | Unvalidated Content-Type header | CAUGHT | Tier 2 async |
| Hardcoded API key | Credential in source | CAUGHT | Tier 1 sync |
| SQL injection via f-string | Unsanitized parameter in query | CAUGHT | Tier 2 async |

Full methodology and raw results: [`benchmarks/README.md`](benchmarks/README.md)
Reproduce: `python benchmarks/cve_benchmark.py`

### Advanced Benchmark — Beyond Grep

The CVE cases above are mostly catchable by pattern matching. This benchmark tests whether Vigil's reasoning goes further. Each case requires cross-context analysis, architectural understanding, library-specific knowledge, or intent-code mismatch detection.

| Case | Vulnerability | Grep Catches? | Result |
|---|---|---|---|
| SSRF | User-controlled URL to `requests.get()` | No | CAUGHT — Tier 2 used brief invariant `no-ssrf` |
| Command injection | `os.system()` with user path | Yes | CAUGHT — Tier 1 pattern match |
| Path traversal | `send_file(f"uploads/{user_input}")` | No | CAUGHT — Tier 2 combination reasoning |
| Indirect RCE | `pickle.loads()` in call #1, `request.body` passed in call #2 | No | CAUGHT — Tier 2 traced ASSUMES violation across writes |
| XXE via lxml | `etree.fromstring(user_data)` default entity resolution | No | CAUGHT — after prompt fix (see below) |
| Auth bypass | Intent claims auth check, zero auth in code | No | CAUGHT — pure intent-code mismatch |

**5/6 cases require reasoning that grep-based scanners cannot do.**

Full results: [`benchmarks/advanced_results.jsonl`](benchmarks/advanced_results.jsonl)
Reproduce: `python benchmarks/advanced_benchmark.py`

#### Documented False Negative: XXE

Vigil initially missed the XXE case. Tier 1 saw `etree.fromstring(user_data)` but returned `CLEAR_PASS` because it lacked knowledge that `lxml` enables external entity resolution by default. Since Tier 1 cleared it, Tier 2 was never invoked.

Fix: added two rules to the prompts. Tier 1 now returns `AMBIGUOUS` on any XML parser + user input combination. Tier 2 has explicit `lxml`-specific knowledge about unsafe defaults.

This is documented rather than hidden because it shows the improvement loop the dataset pipeline is designed to support: find a gap, fix the prompt, verify the fix, record it.

---

## Test Suite

85 tests across 8 phases.

```bash
pytest -v                    # full suite
pytest -v --durations=10     # with timing (identify slow tests)
pytest --cov=. --cov-report=term-missing   # with coverage
```

By phase:

```bash
pytest tests/test_models.py     # Phase 1 — Pydantic schemas, IntentMessage, Verdict, ArchitectureBrief
pytest tests/test_phase2.py     # Phase 2 — MCP server startup, tool registration, brief generator parsing
pytest tests/test_phase3.py     # Phase 3 — classifier routing, diff inference, Tier 1 verdict parsing
pytest tests/test_phase4.py     # Phase 4 — Tier 2 async, pending_block injection, context compression
pytest tests/test_e2e.py        # Phase 5 — 7 end-to-end pipeline scenarios
pytest tests/test_phase6.py     # Phase 6 — invariant grounding, severity thresholds, WARN, dataset export
pytest tests/test_phase7.py     # Phase 7 — ASSUMES verifier, semantic expansion, infra scope detection
pytest tests/test_phase8.py     # Phase 8 — full diff storage, negative samples, brief quality validation
```

Notable test coverage in [`tests/test_e2e.py`](tests/test_e2e.py):

- Hardcoded secret → Tier 1 `CLEAR_BLOCK`, file not written, `invariant_violated` set correctly
- Clean utility function → `SKIP`, no model called at all
- Business logic flaw → `AMBIGUOUS` → Tier 2 `BLOCK` → `DEFERRED BLOCK` on next call, second file not written
- PII in logs → `CLEAR_BLOCK` with correct invariant reference
- Empty INTENT (agent passed no `affects`) → diff inference routes to Tier 1 anyway
- Audit report generation → finding appears in `vigil_cli.py report` output

Notable test coverage in [`tests/test_phase4.py`](tests/test_phase4.py):

- `pending_block` injection verified end-to-end: Call #1 AMBIGUOUS → background Tier 2 BLOCK → Call #2 halted, file not written
- Context compression at 100 entries: `BLOCK` entries never removed regardless of age
- Tier 2 exception handling: failure returns `APPROVE`, session continues uninterrupted

Notable test coverage in [`tests/test_phase7.py`](tests/test_phase7.py):

- "authentication handled upstream" → semantic expansion → maps to `middleware/`, `auth/` directories
- `@require_auth` decorator in scanned file → `VERIFIED` without any LLM call
- VPC assumption → `_is_infra_assumption()` → `INFRASTRUCTURE` scope, skips codebase scan entirely
- Vague LLM evidence ("the code handles auth correctly") → `_validate_llm_evidence()` → downgraded to `INCONCLUSIVE`

---

## Project Structure

```
vigil/
├── server/
│   ├── main.py           # MCP server entrypoint, session init, vigil_* tool registration
│   ├── interceptor.py    # Core pipeline: classifier → Tier 1 → file write → Tier 2 async
│   ├── classifier.py     # INTENT classifier, SENSITIVE_KEYWORDS, ALWAYS_RELEVANT_PATTERNS
│   ├── tier1.py          # Haiku, sync, <200ms, _validate_invariant() post-parse
│   ├── tier2.py          # Opus, async, full session context, _validate_invariant() post-parse
│   └── context.py        # Session history, call counter, compression at 100 entries
├── brief/
│   ├── generator.py      # Brief generation, validate_brief(), retry on quality failure
│   └── schema.py         # ArchitectureBrief, SecurityInvariant, TrustBoundary
├── models/
│   ├── intent.py         # IntentMessage — required tool parameters, is_empty, is_malformed
│   ├── verdict.py        # Verdict, ToolCallResult — BLOCK/WARN/CLEAR_PASS/SKIP/AMBIGUOUS
│   └── context_entry.py  # ContextEntry — one per tool call in session history
├── audit/
│   ├── logger.py         # JSONL log, full diff files for diffs >600 chars
│   ├── report.py         # Markdown report from session log
│   ├── dataset.py        # Fine-tuning exporter — AMBIGUOUS→Tier2 pairs + optional negatives
│   └── verifier.py       # ASSUMES verifier — keyword map → static scan → LLM fallback
├── prompts/
│   ├── brief_generation.txt
│   ├── tier1.txt         # Calibrated examples, lxml/XXE rules, INVARIANT GROUNDING RULE
│   └── tier2.txt         # Full reasoning instructions, library knowledge, grounding rule
├── benchmarks/
│   ├── cve_benchmark.py          # 5 CVE pattern cases
│   ├── advanced_benchmark.py     # 6 beyond-grep reasoning cases
│   ├── results.jsonl             # CVE benchmark raw results
│   ├── advanced_results.jsonl    # Advanced benchmark raw results
│   └── README.md                 # Methodology, honest notes, per-case analysis
├── tests/
│   ├── test_models.py    # Phase 1 — 9 tests
│   ├── test_phase2.py    # Phase 2 — 6 tests
│   ├── test_phase3.py    # Phase 3 — 14 tests
│   ├── test_phase4.py    # Phase 4 — 6 tests
│   ├── test_e2e.py       # Phase 5 — 7 tests
│   ├── test_phase6.py    # Phase 6 — 10 tests
│   ├── test_phase7.py    # Phase 7 — 18 tests
│   └── test_phase8.py    # Phase 8 — 15 tests
├── smoke_test.py         # Manual pipeline validation
├── vigil_cli.py          # Audit log CLI
└── CLAUDE.md             # Drop-in Claude Code integration template
```

---

## Design Decisions

**Why MCP and not post-commit scanning**

The agent's context disappears after the session. A post-hoc scanner sees the file but not why it was written, what was assumed, or what was written three files ago that makes this file dangerous. MCP tool calls are the only point in the pipeline where intent, reasoning, and code exist simultaneously before anything is persisted.

**Why INTENT as required schema parameters**

An earlier design asked the agent to emit a structured `INTENT` block as prose before each write. Soft dependency — the agent forgets, rushes, or writes garbage. Making INTENT fields required parameters in the tool schema means omitting them fails schema validation before the interceptor sees anything. The classifier's diff inference handles the cases where the agent passes empty values.

**Why two tiers**

A single frontier model running synchronously on every write is too slow and too expensive. The classifier eliminates most calls before any model runs. Tier 1 handles the obvious cases fast. Tier 2 only runs on ambiguous cases, async, without blocking the agent. The tradeoff is that Tier 2 findings are deferred by one tool call — acceptable, because the finding still interrupts the session before more code builds on the vulnerability.

**Why fail-open**

A security tool that breaks a coding session on a quota error or network timeout gets disabled. Tier 1 returns `AMBIGUOUS` on failure. Tier 2 returns `APPROVE` on failure. Every failure is logged. The audit trail stays complete even when the models are unavailable.

**Why scoped crawling in the ASSUMES verifier**

Passing the whole codebase to an LLM hits token limits on any real project and produces noisy results. The verifier maps assumption keywords to likely directories, runs regex detection first, and only calls the LLM for the ambiguous middle case — relevant code found but unclear if it satisfies the assumption. Most cases resolve without a model call.

---

## Roadmap

**`vigil init` installer** — one command to set up `.mcp.json`, `CLAUDE.md`, and `.env` in any project. Currently requires manual file copying.

**Interactive brief review** — show the generated brief and let the developer edit invariants before the session starts. Brief quality is the main variable in Tier 2 accuracy.

**Override mechanism** — let the developer confirm a BLOCK and proceed with a required justification. Currently a block is a hard stop.

**Independent evaluation** — run against BigVul or CVEfixes (real vulnerable commits from open source projects). Measure true positive rate, false positive rate, and comparison against Semgrep and CodeQL on the same corpus. The synthetic benchmark cases here are a starting point, not a production evaluation.

**Fine-tuning pipeline** — `export-dataset --negatives` already collects labeled AMBIGUOUS → resolution pairs. After enough sessions, use these to fine-tune a smaller Tier 1 model that improves on project-specific patterns without prompt engineering.

---

*85 tests · 8 phases · 5/5 CVE patterns · 6/6 advanced benchmark*
