# Vigil Integration

This project uses **Vigil** — a real-time security watcher that intercepts file writes
and analyzes them for security issues before they land.

## File Writing Tools

You have access to three file-writing tools provided by Vigil. **You must use these
instead of the standard write_file, str_replace, and create_file tools.**

- `vigil_write_file` — replaces `write_file`
- `vigil_str_replace` — replaces `str_replace`
- `vigil_create_file` — replaces `create_file`

## Required Parameters

Every Vigil tool call requires these additional parameters:

| Parameter | Type | What to put |
|---|---|---|
| `intent` | string | One sentence: what does this code block do? |
| `reason` | string | Why is this decision being made? |
| `affects` | list[str] | Which security domains does this touch? |
| `invariants_touched` | list[str] | Any invariants from the brief being relaxed? |
| `assumes` | list[str] | Any external guarantees being relied on? |

**Valid `affects` values:** `auth`, `crypto`, `logging`, `data-exposure`,
`input-validation`, `file-system`, `network`, `none`

Set `affects=[]`, `invariants_touched=[]`, and `assumes=[]` explicitly if none apply.
Do **not** omit them.

## Examples

```python
# Creating a route that touches auth
vigil_create_file(
    path="src/routes/checkout.py",
    file_text="...",
    intent="implementing checkout route with JWT validation",
    reason="core payment flow per architecture brief",
    affects=["auth", "data-exposure"],
    invariants_touched=[],
    assumes=["JWT middleware active on /api/v1/ routes"]
)

# A pure logic change with no security implications
vigil_str_replace(
    path="src/utils/formatting.py",
    old_str="def format_price(p): return p",
    new_str="def format_price(p): return f'${p:.2f}'",
    intent="formatting price display",
    reason="UX improvement",
    affects=[],
    invariants_touched=[],
    assumes=[]
)
```

## Vigil Responses

Vigil will respond to every tool call with one of:

- `[Vigil] APPROVE` — proceed normally
- `[Vigil] SKIP` — not security relevant, proceeded
- `[Vigil] BLOCK` — violation found, **file was NOT written**, you must fix before continuing
- `[Vigil] AMBIGUOUS` — file written, deep analysis running in background
- `[Vigil] DEFERRED BLOCK` — a prior async finding requires your attention **before proceeding**

When you receive a BLOCK or DEFERRED BLOCK, read the finding carefully and address it
before making any further file changes.
