# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.tools.get_affected_entities."""

from __future__ import annotations

import pytest

import src.tools.get_affected_entities as _mod
from src.tools.get_affected_entities import get_affected_entities, set_current_event

EVENT_ARN = "arn:aws:health:us-east-1::event/EKS/TEST/001"


def _make_event(entities: list | dict) -> dict:
    return {"eventArn": EVENT_ARN, "affectedEntities": entities}


class TestWithListEntities:
    def setup_method(self):
        set_current_event(_make_event([
            {"entityValue": "cluster-1", "entityStatus": "IMPAIRED", "lastUpdatedTime": "2026-01-01T00:00:00Z", "tags": {}},
            {"entityValue": "cluster-2", "entityStatus": "UNIMPAIRED", "lastUpdatedTime": "2026-01-01T00:00:00Z", "tags": {"env": "prod"}},
        ]))

    def test_returns_entities(self):
        result = get_affected_entities._tool_func(event_arn=EVENT_ARN)
        assert len(result) == 2

    def test_entity_fields_present(self):
        result = get_affected_entities._tool_func(event_arn=EVENT_ARN)
        assert result[0]["entityValue"] == "cluster-1"
        assert result[0]["entityStatus"] == "IMPAIRED"

    def test_tags_included(self):
        result = get_affected_entities._tool_func(event_arn=EVENT_ARN)
        prod_entity = next(e for e in result if e["entityValue"] == "cluster-2")
        assert prod_entity["tags"] == {"env": "prod"}


class TestWithDictEntities:
    def setup_method(self):
        set_current_event(_make_event({
            "cluster-1": {"entityValue": "cluster-1", "entityStatus": "IMPAIRED", "lastUpdatedTime": "", "tags": {}},
        }))

    def test_dict_entities_returned_as_list(self):
        result = get_affected_entities._tool_func(event_arn=EVENT_ARN)
        assert isinstance(result, list)
        assert len(result) == 1


class TestEdgeCases:
    def test_no_event_injected_returns_empty(self):
        set_current_event({})
        result = get_affected_entities._tool_func(event_arn=EVENT_ARN)
        assert result == []

    def test_arn_mismatch_returns_empty(self):
        set_current_event(_make_event([{"entityValue": "e1", "entityStatus": "IMPAIRED", "lastUpdatedTime": "", "tags": {}}]))
        result = get_affected_entities._tool_func(event_arn="arn:aws:health:::wrong-arn")
        assert result == []

    def test_empty_entities_list(self):
        set_current_event(_make_event([]))
        result = get_affected_entities._tool_func(event_arn=EVENT_ARN)
        assert result == []
