# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for devops-agent-skill/agents-md/AGENTS-incident-triage.md.

Task 10, working spec feat-devops-agent-enrichment, design.md SS3.5:
"devops-agent-skill/agents-md/AGENTS-incident-triage.md (<= 120 lines,
<= 25 KB)". Also checks the framework's own devops-agent-skill steering
constraints table ("Max size: 25 KB per file", "Format: Markdown only").
"""

from __future__ import annotations

import os
from pathlib import Path

_AGENTS_MD = (
    Path(__file__).parents[3]
    / "devops-agent-skill"
    / "agents-md"
    / "AGENTS-incident-triage.md"
)

_MAX_SIZE_BYTES = 25 * 1024  # 25 KB, per design SS3.5 and the devops-agent-skill steering
_MAX_LINES = 120  # per design SS3.5


class TestAgentsMdExistsAndIsMarkdown:
    def test_file_exists(self):
        assert _AGENTS_MD.exists()

    def test_file_extension_is_markdown(self):
        assert _AGENTS_MD.suffix == ".md"

    def test_no_yaml_frontmatter(self):
        """Unlike SKILL.md, AGENTS.md files have no frontmatter block per
        the devops-agent-skill steering's own template — they are plain
        Markdown instructions loaded verbatim."""
        content = _AGENTS_MD.read_text()
        assert not content.startswith("---\n")


class TestAgentsMdSizeLimits:
    def test_under_25kb(self):
        size = _AGENTS_MD.stat().st_size
        assert size <= _MAX_SIZE_BYTES, f"AGENTS-incident-triage.md is {size} bytes, exceeds the 25KB limit"

    def test_under_120_lines(self):
        line_count = len(_AGENTS_MD.read_text().splitlines())
        assert line_count <= _MAX_LINES, f"AGENTS-incident-triage.md is {line_count} lines, exceeds the 120-line limit"


class TestAgentsMdContract:
    """Design SS3.5's explicit content requirements for this file."""

    def test_mentions_health_triage_tag(self):
        content = _AGENTS_MD.read_text()
        assert "HEALTH_TRIAGE" in content

    def test_instructs_not_to_reclassify(self):
        content = _AGENTS_MD.read_text()
        content_lower = content.lower()
        assert "re-classify" in content_lower or "reclassify" in content_lower or "recompute" in content_lower

    def test_instructs_scoping_to_listed_accounts_and_region(self):
        content = _AGENTS_MD.read_text()
        content_lower = content.lower()
        assert "accounts" in content_lower
        assert "region" in content_lower

    def test_instructs_skipping_closed_events(self):
        content = _AGENTS_MD.read_text()
        assert "closed" in content.lower()

    def test_states_affected_resources_table_is_mandatory(self):
        content = _AGENTS_MD.read_text()
        assert "Affected resources" in content
        assert "mandatory" in content.lower()

    def test_prohibits_touching_external_tickets(self):
        content = _AGENTS_MD.read_text()
        content_lower = content.lower()
        assert "ticket" in content_lower
        assert "jira" in content_lower or "servicenow" in content_lower

    def test_is_incident_triage_agent_type(self):
        """Filename and content both signal INCIDENT_TRIAGE targeting —
        the actual agent_type metadata is applied at deploy time (per the
        devops-agent-skill steering's create-asset command), but the file
        itself should be unambiguous about which type it targets."""
        assert "incident-triage" in _AGENTS_MD.name.lower() or "incident_triage" in _AGENTS_MD.name.lower()
        assert "INCIDENT_TRIAGE" in _AGENTS_MD.read_text()


class TestAgentsMdNoExecutableContent:
    def test_agents_md_directory_has_no_executables(self):
        agents_md_dir = _AGENTS_MD.parent
        forbidden_extensions = (".py", ".sh", ".js", ".ts", ".exe", ".bin")
        for root, dirs, files in os.walk(agents_md_dir):
            for f in files:
                assert not f.endswith(forbidden_extensions), (
                    f"Executable-looking file not allowed: {os.path.join(root, f)}"
                )
