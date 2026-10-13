# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.triage.routing.resolve_team."""

from __future__ import annotations

import pytest

from src.triage.routing import resolve_team

_TABLE = [
    {"ruleType": "TAG", "key": "Team=payments", "team": "Payments-Team", "snsTopicArn": "arn:tag"},
    {"ruleType": "ACCOUNT", "key": "111111111111", "team": "Account-Team", "snsTopicArn": "arn:acct"},
    {"ruleType": "OU", "key": "Root/Prod", "team": "OU-Team", "snsTopicArn": "arn:ou"},
    {"ruleType": "SERVICE", "key": "EKS", "team": "EKS-Team", "snsTopicArn": "arn:svc"},
    {"ruleType": "DEFAULT", "key": "*", "team": "Default-Team", "snsTopicArn": "arn:default"},
]


class TestPrecedenceOrder:
    def test_tag_wins_over_everything(self):
        entities = [{"entityValue": "e1", "tags": {"Team": "payments"}}]
        accounts = [{"account_id": "111111111111", "ou_path": "Root/Prod"}]
        result = resolve_team(entities, accounts, "EKS", routing_table=_TABLE)
        assert result["team"] == "Payments-Team"
        assert result["routing"] == "tag"

    def test_account_wins_over_ou_and_service(self):
        entities = [{"entityValue": "e1", "tags": {}}]
        accounts = [{"account_id": "111111111111", "ou_path": "Root/Prod"}]
        result = resolve_team(entities, accounts, "EKS", routing_table=_TABLE)
        assert result["team"] == "Account-Team"
        assert result["routing"] == "account"

    def test_ou_wins_over_service(self):
        entities = [{"entityValue": "e1", "tags": {}}]
        accounts = [{"account_id": "222222222222", "ou_path": "Root/Prod"}]
        result = resolve_team(entities, accounts, "EKS", routing_table=_TABLE)
        assert result["team"] == "OU-Team"
        assert result["routing"] == "ou"

    def test_service_wins_over_default(self):
        entities = []
        accounts = [{"account_id": "999999999999", "ou_path": "Root/Other"}]
        result = resolve_team(entities, accounts, "EKS", routing_table=_TABLE)
        assert result["team"] == "EKS-Team"
        assert result["routing"] == "service"

    def test_default_when_nothing_matches(self):
        entities = []
        accounts = [{"account_id": "999999999999", "ou_path": "Root/Other"}]
        result = resolve_team(entities, accounts, "UNKNOWN_SERVICE", routing_table=_TABLE)
        assert result["team"] == "Default-Team"
        assert result["routing"] == "default"


class TestChannelsIncluded:
    def test_channels_dict_present(self):
        result = resolve_team([], [], "UNKNOWN", routing_table=_TABLE)
        assert "channels" in result
        assert result["channels"]["snsTopicArn"] == "arn:default"


class TestMalformedTable:
    def test_empty_table_returns_hardcoded_fallback(self):
        result = resolve_team([], [], "EKS", routing_table=[])
        assert result["team"] == "Platform-Operations"
        assert result["routing"] == "fallback"

    def test_no_default_rule_returns_fallback(self):
        table = [{"ruleType": "SERVICE", "key": "RDS", "team": "DB-Team"}]
        result = resolve_team([], [], "EKS", routing_table=table)
        assert result["routing"] == "fallback"

    def test_malformed_entity_tags_skipped_safely(self):
        entities = [{"entityValue": "e1", "tags": "not-a-dict"}]
        result = resolve_team(entities, [], "EKS", routing_table=_TABLE)
        assert result["team"] == "EKS-Team"  # falls through to service rule


class TestNeverRaises:
    def test_none_routing_table_loads_default_seed(self):
        # No explicit routing_table -> loads config/routing.example.json
        result = resolve_team([], [], "UNKNOWN_SERVICE_XYZ")
        assert result["team"]  # some team is always returned
