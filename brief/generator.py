import anthropic
import os
import re
from pathlib import Path
from brief.schema import ArchitectureBrief, SecurityInvariant, TrustBoundary


def _load_prompt() -> str:
    return Path("prompts/brief_generation.txt").read_text()


async def generate_brief(project_prompt: str) -> ArchitectureBrief:
    """
    Calls the reasoning model with the project prompt and parses the
    returned markdown into a structured ArchitectureBrief.
    """
    system_prompt = _load_prompt()

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    response = client.messages.create(
        model="claude-opus-4-5",  # reasoning model for Phase 1 brief generation
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": project_prompt}],
    )

    raw_markdown = response.content[0].text
    return _parse_brief(raw_markdown)


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
