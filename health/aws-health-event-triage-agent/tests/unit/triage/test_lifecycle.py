# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.triage.lifecycle.should_close."""

from __future__ import annotations

import pytest

from src.triage.lifecycle import should_close


class TestStatusCodeClosed:
    def test_closed_status_returns_true(self):
        assert should_close({"statusCode": "closed", "affectedEntities": {}}) is True

    def test_closed_case_insensitive(self):
        assert should_close({"statusCode": "CLOSED", "affectedEntities": {}}) is True

    def test_open_status_no_entities_returns_false(self):
        assert should_close({"statusCode": "open", "affectedEntities": {}}) is False

    def test_upcoming_status_no_entities_returns_false(self):
        assert should_close({"statusCode": "upcoming", "affectedEntities": {}}) is False


class TestAllEntitiesResolved:
    def test_all_resolved_returns_true(self):
        record = {
            "statusCode": "open",
            "affectedEntities": {
                "e1": {"entityValue": "e1", "entityStatus": "RESOLVED"},
                "e2": {"entityValue": "e2", "entityStatus": "RESOLVED"},
            },
        }
        assert should_close(record) is True

    def test_partial_resolution_returns_false(self):
        record = {
            "statusCode": "open",
            "affectedEntities": {
                "e1": {"entityValue": "e1", "entityStatus": "RESOLVED"},
                "e2": {"entityValue": "e2", "entityStatus": "IMPAIRED"},
            },
        }
        assert should_close(record) is False

    def test_case_insensitive_resolved(self):
        record = {
            "statusCode": "open",
            "affectedEntities": {"e1": {"entityValue": "e1", "entityStatus": "resolved"}},
        }
        assert should_close(record) is True

    def test_list_form_entities_accepted(self):
        record = {
            "statusCode": "open",
            "affectedEntities": [
                {"entityValue": "e1", "entityStatus": "RESOLVED"},
            ],
        }
        assert should_close(record) is True


class TestNoEntities:
    def test_open_status_empty_entities_returns_false(self):
        assert should_close({"statusCode": "open", "affectedEntities": {}}) is False

    def test_missing_entities_key_returns_false(self):
        assert should_close({"statusCode": "open"}) is False


class TestNeverRaises:
    def test_malformed_entities_type_returns_false(self):
        assert should_close({"statusCode": "open", "affectedEntities": "not-a-dict-or-list"}) is False

    def test_entity_missing_status_treated_as_unresolved(self):
        record = {
            "statusCode": "open",
            "affectedEntities": {"e1": {"entityValue": "e1"}},
        }
        assert should_close(record) is False

    def test_non_dict_entity_in_list_does_not_raise(self):
        record = {"statusCode": "open", "affectedEntities": ["not-a-dict"]}
        assert should_close(record) is False
