# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for devops-agent-skill/SKILL.md's format and contract.

Task 10, working spec feat-devops-agent-enrichment. No API calls, no
network — validates the skill's frontmatter, size, and (per the
devops-agent-skill steering's own guardrails) that it contains no
executable content, since skills are non-executable Markdown documents.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_SKILL_ROOT = Path(__file__).parents[3] / "devops-agent-skill"
_SKILL_MD = _SKILL_ROOT / "SKILL.md"
_MAX_PACKAGE_SIZE_BYTES = 6 * 1024 * 1024  # 6MB, per devops-agent-skill steering


def _frontmatter(path: Path) -> dict:
    """Minimal top-level-only YAML frontmatter parser.

    SKILL.md's frontmatter is exactly two simple scalar keys (name,
    description) with no nesting, lists, or multi-line block scalars — a
    hand-rolled parser avoids adding pyyaml as a new pinned dependency
    (requirements.txt) for what a test-only file needs. If a future
    SKILL.md frontmatter ever needs real YAML features, switch to pyyaml
    (already present transitively, but not pinned) at that point.
    """
    content = path.read_text()
    assert content.startswith("---\n"), f"{path} must start with YAML frontmatter"
    parts = content.split("---", 2)
    assert len(parts) >= 3, f"{path} frontmatter is not properly delimited"
    result: dict = {}
    current_key: str | None = None
    for line in parts[1].splitlines():
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and current_key:
            # Continuation line of a multi-line scalar value (no '>' or '|'
            # YAML block-scalar indicators used in this file's frontmatter
            # — a folded-style plain multi-line string, joined with a
            # single space, matching how PyYAML would fold it too).
            result[current_key] = (result[current_key] + " " + line.strip()).strip()
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            current_key = key.strip()
            result[current_key] = value.strip()
    return result


class TestSkillMdFrontmatter:
    def test_skill_md_exists(self):
        assert _SKILL_MD.exists()

    def test_frontmatter_has_name(self):
        fm = _frontmatter(_SKILL_MD)
        assert "name" in fm
        assert fm["name"] == "health-event-impact-assessment"

    def test_frontmatter_has_description(self):
        fm = _frontmatter(_SKILL_MD)
        assert "description" in fm
        # devops-agent-skill steering: description must be 100+ chars,
        # specific enough for DevOps Agent to decide when to activate it.
        assert len(fm["description"]) >= 100

    def test_frontmatter_description_mentions_deadline_class_events(self):
        """Task 10 retargeted this skill's description to also cover
        deadline-class enrichment (not just impact-assessment) -- confirm
        the description was actually updated, not just the body."""
        fm = _frontmatter(_SKILL_MD)
        description_lower = fm["description"].lower()
        assert "deadline" in description_lower or "breaking" in description_lower

    def test_agent_type_targeting_is_not_a_frontmatter_field(self):
        """Agent-type targeting (task 10: retargeted to INCIDENT_RCA) is
        deploy-time --metadata, per the devops-agent-skill steering's own
        deploy command shape -- NOT a SKILL.md frontmatter field. This test
        guards against a future edit accidentally adding an
        agent_type/agent_types key to the frontmatter under the mistaken
        belief that it does the targeting."""
        fm = _frontmatter(_SKILL_MD)
        assert "agent_type" not in fm
        assert "agent_types" not in fm


class TestSkillMdContract:
    """The parser contract this SKILL.md's Output Format section documents
    must exactly match what the real parsers
    (src/devops_agent/affected_resources.py,
    src/devops_agent/readiness_outcome.py) expect -- these tests check the
    DOCUMENTATION states the contract correctly, not that the parsers work
    (those have their own test suites)."""

    def test_mentions_incident_rca_targeting(self):
        content = _SKILL_MD.read_text()
        assert "INCIDENT_RCA" in content

    def test_output_format_includes_affected_resources_header_row(self):
        content = _SKILL_MD.read_text()
        assert "| account | resource_arn | resource_type | current_version | status | evidence |" in content

    def test_output_format_includes_dependents_verified_line(self):
        content = _SKILL_MD.read_text()
        assert "Dependents verified" in content

    def test_output_format_includes_readiness_assessment_contract(self):
        content = _SKILL_MD.read_text()
        assert "FEASIBILITY:" in content
        assert "BLOCKERS:" in content
        assert "RISK:" in content
        assert "ROLLBACK_AVAILABLE:" in content

    def test_status_vocabulary_matches_the_real_parser(self):
        """The five-value status vocabulary documented in SKILL.md must
        match src/devops_agent/affected_resources.py's _VALID_STATUSES
        exactly -- a documentation/code drift here would tell the agent
        to use a vocabulary the parser doesn't recognise."""
        from src.devops_agent.affected_resources import _VALID_STATUSES

        content = _SKILL_MD.read_text()
        for status in _VALID_STATUSES:
            assert status in content, f"status value {status!r} not documented in SKILL.md"

    def test_impact_locus_dependent_branch_documented(self):
        content = _SKILL_MD.read_text()
        assert "impactLocus=dependent" in content
        assert "trust store" in content.lower()

    def test_event_snapshot_tag_reading_step_documented(self):
        content = _SKILL_MD.read_text()
        assert "EVENT_SNAPSHOT" in content

    def test_e32_maintenance_checks_documented(self):
        """The E3.2 checks (single-replica Deployments, blocking PDBs,
        standalone pods; MSK offline-partition history) must be described
        in the skill, since the deleted prechecks no longer run in code."""
        content = _SKILL_MD.read_text()
        content_lower = content.lower()
        assert "single-replica" in content_lower or "single replica" in content_lower
        assert "poddisruptionbudget" in content_lower or "pdb" in content_lower
        assert "offline-partition" in content_lower or "offline partition" in content_lower


class TestSkillPackageGuardrails:
    """devops-agent-skill steering's guardrails: no scripts, no executable
    files, under 6MB total."""

    def test_no_executable_files_in_skill_directory(self):
        forbidden_extensions = (".py", ".sh", ".js", ".ts", ".exe", ".bin")
        for root, dirs, files in os.walk(_SKILL_ROOT):
            assert "scripts" not in dirs, "scripts/ directory not allowed in a skill package"
            for f in files:
                assert not f.endswith(forbidden_extensions), (
                    f"Executable-looking file not allowed in skill package: {os.path.join(root, f)}"
                )

    def test_package_size_under_limit(self):
        total = sum(
            os.path.getsize(os.path.join(root, f))
            for root, _, files in os.walk(_SKILL_ROOT)
            for f in files
        )
        assert total < _MAX_PACKAGE_SIZE_BYTES
