import anthropic
import os
import re
from pathlib import Path
from brief.schema import ArchitectureBrief, SecurityInvariant, TrustBoundary


class BriefQualityError(Exception):
    """Raised when generated brief doesn't meet minimum quality thresholds."""
    pass


def validate_brief(brief: ArchitectureBrief) -> list[str]:
    """
    Validates brief quality. Returns list of issues found.
    Empty list = brief is acceptable.
    """
    issues = []

    if len(brief.invariants) < 2:
        issues.append(
            f"Only {len(brief.invariants)} invariant(s) defined. "
            "Need at least 2 specific, falsifiable invariants. "
            "Add more detail about what must ALWAYS be true in your system."
        )

    vague_invariant_patterns = [
        "handle security", "be secure", "follow best practices",
        "implement correctly", "ensure security", "handle correctly",
        "be safe", "avoid vulnerabilities"
    ]
    for inv in brief.invariants:
        desc_lower = inv.description.lower()
        if any(p in desc_lower for p in vague_invariant_patterns):
            issues.append(
                f"Invariant '{inv.id}' is too vague: '{inv.description}'. "
                "Invariants must be falsifiable assertions, e.g. "
                "'Payment data must never appear in any log call'."
            )

    if not brief.trust_boundaries:
        issues.append(
            "No trust boundaries defined. "
            "Specify which endpoints are PUBLIC, AUTHENTICATED, or INTERNAL ONLY."
        )

    if not brief.auth_model or len(brief.auth_model.strip()) < 20:
        issues.append(
            "Auth model is missing or too brief. "
            "Describe how authentication and authorization work in your system."
        )

    vague_purpose_patterns = ["web app", "web application", "backend", "api", "service"]
    purpose_lower = brief.system_purpose.lower().strip()
    if len(purpose_lower) < 40:
        issues.append(
            "System purpose is too brief. "
            "Describe what the system does, who uses it, and what data it handles."
        )

    return issues


def _load_prompt() -> str:
    return Path("prompts/brief_generation.txt").read_text()


async def generate_brief(project_prompt: str) -> ArchitectureBrief:
    """
    Generates Architecture Brief. If quality validation fails, retries once
    with an augmented prompt that includes the specific issues found.
    """
    system_prompt = _load_prompt()
    client = anthropic.AsyncAnthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    # First attempt
    response = await client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": project_prompt}]
    )
    raw_markdown = response.content[0].text
    brief = _parse_brief(raw_markdown)

    issues = validate_brief(brief)
    if not issues:
        return brief

    # One retry with explicit quality requirements
    issues_text = "\n".join(f"- {issue}" for issue in issues)
    augmented_prompt = f"""{project_prompt}

The previous brief had these quality issues that you must fix:
{issues_text}

Please regenerate the brief addressing all of these issues specifically.
Invariants must be falsifiable assertions, not generic security advice."""

    response2 = await client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": augmented_prompt}]
    )
    raw_markdown2 = response2.content[0].text
    brief2 = _parse_brief(raw_markdown2)

    # Return second attempt regardless — don't block on quality
    remaining_issues = validate_brief(brief2)
    if remaining_issues:
        print(f"[Vigil] Warning: Brief quality issues remain after retry:")
        for issue in remaining_issues:
            print(f"[Vigil]   - {issue}")
        print("[Vigil] Proceeding with best available brief. Consider improving your VIGIL_PROJECT_PROMPT.")

    return brief2


def _parse_brief(markdown: str) -> ArchitectureBrief:
    """
    Parses the structured markdown brief into an ArchitectureBrief object.
    If parsing fails on any section, uses a safe empty default and continues.
    """
    sections = _extract_sections(markdown)

    return ArchitectureBrief(
        system_purpose=sections.get("System Purpose", "").strip(),
        trust_boundaries=_parse_trust_boundaries(sections.get("Trust Boundaries", "")),
        auth_model=sections.get("Auth Model", "").strip(),
        data_flows=_parse_list(sections.get("Data Flows", "")),
        invariants=_parse_invariants(sections.get("Security Invariants", "")),
        sensitive_operations=_parse_list(sections.get("Sensitive Operations", "")),
        raw_markdown=markdown,
    )


def _extract_sections(markdown: str) -> dict[str, str]:
    """Split markdown into {section_name: content} dict using ## headings."""
    sections: dict[str, str] = {}
    current_section: str | None = None
    current_lines: list[str] = []

    for line in markdown.splitlines():
        if line.startswith("## "):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = line[3:].strip()
            current_lines = []
        elif current_section:
            current_lines.append(line)

    # Flush the last section
    if current_section:
        sections[current_section] = "\n".join(current_lines).strip()

    return sections


def _parse_list(text: str) -> list[str]:
    """Extract bullet items from a markdown list section."""
    return [
        line.lstrip("-•* ").strip()
        for line in text.splitlines()
        if line.strip() and line.strip().startswith(("-", "•", "*"))
    ]


def _parse_trust_boundaries(text: str) -> list[TrustBoundary]:
    """Parse '- LABEL: /pattern1, /pattern2' lines into TrustBoundary objects."""
    boundaries = []
    for line in text.splitlines():
        line = line.strip().lstrip("-•* ").strip()
        if ":" in line:
            label, rest = line.split(":", 1)
            patterns = [p.strip() for p in rest.split(",") if p.strip()]
            boundaries.append(TrustBoundary(label=label.strip(), patterns=patterns))
    return boundaries


def _parse_invariants(text: str) -> list[SecurityInvariant]:
    """Parse '- [ ] id: description' lines into SecurityInvariant objects."""
    invariants = []
    for line in text.splitlines():
        line = line.strip()
        # Matches: - [ ] id: description  or  - [x] id: description
        match = re.match(r"-\s*\[[ x]\]\s*([^:]+):\s*(.+)", line)
        if match:
            inv_id = match.group(1).strip()
            description = match.group(2).strip()
            invariants.append(SecurityInvariant(id=inv_id, description=description))
    return invariants
