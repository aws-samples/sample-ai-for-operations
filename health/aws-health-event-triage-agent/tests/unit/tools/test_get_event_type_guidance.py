# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.tools.get_event_type_guidance."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

import src.tools.get_event_type_guidance as _mod
from src.tools.get_event_type_guidance import get_event_type_guidance, get_impact_locus


def _write_guidance(entries: list, tmp_dir: str) -> str:
    path = os.path.join(tmp_dir, "guidance.json")
    with open(path, "w", encoding='utf-8') as f:
        json.dump(entries, f)
    return path


class TestGuidanceLookup:
    def setup_method(self):
        """Reset the cache before each test."""
        _mod._guidance_cache = None

    def test_known_code_returns_entry(self, tmp_path):
        entries = [{
            "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
            "knownSemantics": "EKS version end-of-support",
            "defaultClassHint": "BREAKING_CHANGE",
            "deadlineHints": ["end of standard support"],
            "notes": "",
        }]
        path = _write_guidance(entries, str(tmp_path))
        os.environ["EVENT_TYPE_GUIDANCE_PATH"] = path
        try:
            result = get_event_type_guidance._tool_func(event_type_code="AWS_EKS_PLANNED_LIFECYCLE_EVENT")
            assert result["defaultClassHint"] == "BREAKING_CHANGE"
            assert result["knownSemantics"] == "EKS version end-of-support"
        finally:
            del os.environ["EVENT_TYPE_GUIDANCE_PATH"]
            _mod._guidance_cache = None

    def test_unknown_code_returns_empty(self, tmp_path):
        path = _write_guidance([], str(tmp_path))
        os.environ["EVENT_TYPE_GUIDANCE_PATH"] = path
        try:
            result = get_event_type_guidance._tool_func(event_type_code="AWS_UNKNOWN_CODE")
            assert result == {}
        finally:
            del os.environ["EVENT_TYPE_GUIDANCE_PATH"]
            _mod._guidance_cache = None

    def test_missing_file_returns_empty(self, tmp_path):
        os.environ["EVENT_TYPE_GUIDANCE_PATH"] = str(tmp_path / "nonexistent.json")
        _mod._guidance_cache = None
        try:
            result = get_event_type_guidance._tool_func(event_type_code="ANYTHING")
            assert result == {}
        finally:
            del os.environ["EVENT_TYPE_GUIDANCE_PATH"]
            _mod._guidance_cache = None


class TestGetImpactLocus:
    """get_impact_locus() — task 0a, working spec feat-devops-agent-enrichment
    req §1a. A precision config lookup, not an agent @tool."""

    def setup_method(self):
        _mod._guidance_cache = None

    def _set_guidance(self, entries: list, tmp_path) -> None:
        path = _write_guidance(entries, str(tmp_path))
        os.environ["EVENT_TYPE_GUIDANCE_PATH"] = path

    def teardown_method(self):
        os.environ.pop("EVENT_TYPE_GUIDANCE_PATH", None)
        _mod._guidance_cache = None

    def test_listed_resource_entry(self, tmp_path):
        self._set_guidance(
            [{"eventTypeCode": "AWS_LAMBDA_RUNTIME_DEPRECATION", "impactLocus": "listed_resource"}],
            tmp_path,
        )
        assert get_impact_locus("AWS_LAMBDA_RUNTIME_DEPRECATION") == "listed_resource"

    def test_dependent_entry(self, tmp_path):
        self._set_guidance(
            [{"eventTypeCode": "AWS_KEYSPACES_TLS_CERTIFICATE_ROTATION", "impactLocus": "dependent"}],
            tmp_path,
        )
        assert get_impact_locus("AWS_KEYSPACES_TLS_CERTIFICATE_ROTATION") == "dependent"

    def test_unknown_code_defaults_to_listed_resource(self, tmp_path):
        self._set_guidance([], tmp_path)
        assert get_impact_locus("AWS_TOTALLY_UNKNOWN_CODE") == "listed_resource"

    def test_entry_with_no_impact_locus_field_defaults_to_listed_resource(self, tmp_path):
        """An entry that predates this field (e.g. one never updated) must
        still default safely rather than raising or returning empty."""
        self._set_guidance(
            [{"eventTypeCode": "AWS_SOME_OLD_ENTRY", "knownSemantics": "no impactLocus field at all"}],
            tmp_path,
        )
        assert get_impact_locus("AWS_SOME_OLD_ENTRY") == "listed_resource"

    def test_entry_with_invalid_impact_locus_value_defaults_to_listed_resource(self, tmp_path):
        self._set_guidance(
            [{"eventTypeCode": "AWS_BAD_VALUE", "impactLocus": "not_a_real_value"}],
            tmp_path,
        )
        assert get_impact_locus("AWS_BAD_VALUE") == "listed_resource"

    def test_missing_file_defaults_to_listed_resource(self, tmp_path):
        os.environ["EVENT_TYPE_GUIDANCE_PATH"] = str(tmp_path / "nonexistent.json")
        _mod._guidance_cache = None
        assert get_impact_locus("ANYTHING") == "listed_resource"

    def test_real_config_file_keyspaces_is_dependent(self):
        """Sanity check against the real shipped config, not just fixtures —
        confirms the actual config/event-type-guidance.json entry this
        change added is wired correctly end-to-end."""
        _mod._guidance_cache = None
        os.environ.pop("EVENT_TYPE_GUIDANCE_PATH", None)
        assert get_impact_locus("AWS_KEYSPACES_TLS_CERTIFICATE_ROTATION") == "dependent"
        _mod._guidance_cache = None

    def test_real_config_file_lambda_deprecation_is_listed_resource(self):
        _mod._guidance_cache = None
        os.environ.pop("EVENT_TYPE_GUIDANCE_PATH", None)
        assert get_impact_locus("AWS_LAMBDA_RUNTIME_DEPRECATION") == "listed_resource"
        _mod._guidance_cache = None
