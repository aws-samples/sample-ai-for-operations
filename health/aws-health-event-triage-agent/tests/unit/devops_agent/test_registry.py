# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.registry.resolve_agent_space."""

from __future__ import annotations

from src.devops_agent.registry import resolve_agent_space, resolve_agent_spaces_by_account

_REGISTRY = [
    {"ruleType": "ACCOUNT_TAG", "key": "Team=payments", "agentSpaceId": "tag-space"},
    {"ruleType": "ACCOUNT", "key": "111111111111", "agentSpaceId": "account-space"},
    {"ruleType": "OU", "key": "Root/Prod", "agentSpaceId": "ou-space"},
    {"ruleType": "DEFAULT", "agentSpaceId": "default-space"},
]


class TestPrecedenceOrder:
    def test_account_tag_wins_over_everything(self):
        contexts = [{"account_id": "111111111111", "ou_path": "Root/Prod", "tags": {"Team": "payments"}}]
        result = resolve_agent_space(["111111111111"], contexts, registry=_REGISTRY)
        assert result["agentSpaceId"] == "tag-space"

    def test_account_wins_over_ou(self):
        contexts = [{"account_id": "111111111111", "ou_path": "Root/Prod", "tags": {}}]
        result = resolve_agent_space(["111111111111"], contexts, registry=_REGISTRY)
        assert result["agentSpaceId"] == "account-space"

    def test_ou_wins_over_default(self):
        contexts = [{"account_id": "222222222222", "ou_path": "Root/Prod", "tags": {}}]
        result = resolve_agent_space(["222222222222"], contexts, registry=_REGISTRY)
        assert result["agentSpaceId"] == "ou-space"

    def test_default_when_nothing_matches(self):
        contexts = [{"account_id": "999999999999", "ou_path": "Root/Other", "tags": {}}]
        result = resolve_agent_space(["999999999999"], contexts, registry=_REGISTRY)
        assert result["agentSpaceId"] == "default-space"


class TestUnmatchedNoDefault:
    def test_returns_none_when_no_default_and_no_match(self):
        registry = [{"ruleType": "ACCOUNT", "key": "111111111111", "agentSpaceId": "account-space"}]
        result = resolve_agent_space(["999999999999"], [], registry=registry)
        assert result is None

    def test_empty_registry_returns_none(self):
        result = resolve_agent_space(["111111111111"], [], registry=[])
        assert result is None


class TestMultipleAffectedAccounts:
    def test_first_matching_account_wins(self):
        contexts = [
            {"account_id": "999999999999", "ou_path": "", "tags": {}},
            {"account_id": "111111111111", "ou_path": "", "tags": {}},
        ]
        result = resolve_agent_space(["999999999999", "111111111111"], contexts, registry=_REGISTRY)
        assert result["agentSpaceId"] == "account-space"


class TestMalformedInput:
    def test_malformed_tags_do_not_raise(self):
        contexts = [{"account_id": "111111111111", "ou_path": "", "tags": "not-a-dict"}]
        result = resolve_agent_space(["111111111111"], contexts, registry=_REGISTRY)
        assert result["agentSpaceId"] == "account-space"  # falls through tag check safely

    def test_malformed_tag_rule_key_skipped(self):
        registry = [
            {"ruleType": "ACCOUNT_TAG", "key": "no-equals-sign", "agentSpaceId": "bad-space"},
            {"ruleType": "DEFAULT", "agentSpaceId": "default-space"},
        ]
        contexts = [{"account_id": "111111111111", "ou_path": "", "tags": {"Team": "x"}}]
        result = resolve_agent_space(["111111111111"], contexts, registry=registry)
        assert result["agentSpaceId"] == "default-space"


class TestLoadsSeedByDefault:
    def test_none_registry_loads_default_seed(self):
        # No explicit registry -> loads config/agent_space_registry.example.json
        result = resolve_agent_space(["000000000000"], [])
        assert result is not None
        assert result["ruleType"] == "DEFAULT"


class TestResolveAgentSpacesByAccount:
    """resolve_agent_spaces_by_account() — task 11, working spec
    feat-devops-agent-enrichment, design §3.0: resolves a space PER
    account, then groups accounts by distinct space. Genuinely different
    from resolve_agent_space() above, which resolves ONE entry for the
    combined account list and cannot tell two BU-space accounts apart."""

    def test_single_account_single_space(self):
        contexts = [{"account_id": "111111111111", "ou_path": "", "tags": {}}]
        result = resolve_agent_spaces_by_account(["111111111111"], contexts, registry=_REGISTRY)
        assert len(result) == 1
        assert result[0]["agentSpaceEntry"]["agentSpaceId"] == "account-space"
        assert result[0]["accounts"] == ["111111111111"]

    def test_two_accounts_same_space_grouped_together(self):
        registry = [{"ruleType": "DEFAULT", "agentSpaceId": "shared-default-space"}]
        contexts = [
            {"account_id": "111111111111", "ou_path": "", "tags": {}},
            {"account_id": "222222222222", "ou_path": "", "tags": {}},
        ]
        result = resolve_agent_spaces_by_account(
            ["111111111111", "222222222222"], contexts, registry=registry
        )
        assert len(result) == 1
        assert result[0]["agentSpaceEntry"]["agentSpaceId"] == "shared-default-space"
        assert result[0]["accounts"] == ["111111111111", "222222222222"]

    def test_two_accounts_different_spaces_grouped_separately(self):
        """The core scenario design §3.0 flow 5 describes: account A ->
        BU-1's space, account B -> BU-2's space -> two distinct groups."""
        registry = [
            {"ruleType": "ACCOUNT", "key": "111111111111", "agentSpaceId": "space-bu1"},
            {"ruleType": "ACCOUNT", "key": "222222222222", "agentSpaceId": "space-bu2"},
        ]
        contexts = [
            {"account_id": "111111111111", "ou_path": "", "tags": {}},
            {"account_id": "222222222222", "ou_path": "", "tags": {}},
        ]
        result = resolve_agent_spaces_by_account(
            ["111111111111", "222222222222"], contexts, registry=registry
        )
        assert len(result) == 2
        space_ids = {g["agentSpaceEntry"]["agentSpaceId"] for g in result}
        assert space_ids == {"space-bu1", "space-bu2"}
        by_space = {g["agentSpaceEntry"]["agentSpaceId"]: g["accounts"] for g in result}
        assert by_space["space-bu1"] == ["111111111111"]
        assert by_space["space-bu2"] == ["222222222222"]

    def test_uncovered_account_grouped_under_none_entry_last(self):
        registry = [{"ruleType": "ACCOUNT", "key": "111111111111", "agentSpaceId": "account-space"}]
        contexts = [
            {"account_id": "111111111111", "ou_path": "", "tags": {}},
            {"account_id": "999999999999", "ou_path": "", "tags": {}},
        ]
        result = resolve_agent_spaces_by_account(
            ["111111111111", "999999999999"], contexts, registry=registry
        )
        assert len(result) == 2
        assert result[-1]["agentSpaceEntry"] is None
        assert result[-1]["accounts"] == ["999999999999"]
        assert result[0]["agentSpaceEntry"]["agentSpaceId"] == "account-space"

    def test_all_accounts_uncovered(self):
        result = resolve_agent_spaces_by_account(["111111111111", "222222222222"], [], registry=[])
        assert len(result) == 1
        assert result[0]["agentSpaceEntry"] is None
        assert result[0]["accounts"] == ["111111111111", "222222222222"]

    def test_empty_affected_accounts_returns_empty_list(self):
        result = resolve_agent_spaces_by_account([], [], registry=_REGISTRY)
        assert result == []

    def test_precedence_still_applies_per_account(self):
        """ACCOUNT_TAG > ACCOUNT > OU > DEFAULT, independently for each
        account, using the same _REGISTRY fixture as TestPrecedenceOrder
        above — proving per-account resolution doesn't accidentally use
        the wrong precedence order."""
        contexts = [
            {"account_id": "111111111111", "ou_path": "Root/Prod", "tags": {"Team": "payments"}},  # ACCOUNT_TAG
            {"account_id": "222222222222", "ou_path": "Root/Prod", "tags": {}},  # OU
            {"account_id": "999999999999", "ou_path": "Root/Other", "tags": {}},  # DEFAULT
        ]
        result = resolve_agent_spaces_by_account(
            ["111111111111", "222222222222", "999999999999"], contexts, registry=_REGISTRY
        )
        by_space = {g["agentSpaceEntry"]["agentSpaceId"]: g["accounts"] for g in result}
        assert by_space["tag-space"] == ["111111111111"]
        assert by_space["ou-space"] == ["222222222222"]
        assert by_space["default-space"] == ["999999999999"]

    def test_two_registry_rules_pointing_at_same_space_id_merge_into_one_group(self):
        """The design's point is 'one investigation per DISTINCT SPACE' --
        if two different registry rules (e.g. an ACCOUNT rule and an OU
        rule) both happen to point at the same agentSpaceId, accounts
        matching either rule must merge into ONE group, not two."""
        registry = [
            {"ruleType": "ACCOUNT", "key": "111111111111", "agentSpaceId": "same-space", "note": "account-rule"},
            {"ruleType": "OU", "key": "Root/Prod", "agentSpaceId": "same-space", "note": "ou-rule"},
        ]
        contexts = [
            {"account_id": "111111111111", "ou_path": "Root/Other", "tags": {}},
            {"account_id": "222222222222", "ou_path": "Root/Prod", "tags": {}},
        ]
        result = resolve_agent_spaces_by_account(
            ["111111111111", "222222222222"], contexts, registry=registry
        )
        assert len(result) == 1
        assert result[0]["accounts"] == ["111111111111", "222222222222"]

    def test_deterministic_order_across_calls(self):
        """Sorted by agentSpaceId, so a caller (the Step Functions Map
        state's input array, ultimately) gets a stable branch order run
        to run — useful for test assertions and for reading execution
        history without the branches appearing to shuffle."""
        registry = [
            {"ruleType": "ACCOUNT", "key": "111111111111", "agentSpaceId": "space-zzz"},
            {"ruleType": "ACCOUNT", "key": "222222222222", "agentSpaceId": "space-aaa"},
        ]
        contexts = [
            {"account_id": "111111111111", "ou_path": "", "tags": {}},
            {"account_id": "222222222222", "ou_path": "", "tags": {}},
        ]
        result = resolve_agent_spaces_by_account(
            ["111111111111", "222222222222"], contexts, registry=registry
        )
        assert [g["agentSpaceEntry"]["agentSpaceId"] for g in result] == ["space-aaa", "space-zzz"]

    def test_none_registry_loads_default_seed(self):
        result = resolve_agent_spaces_by_account(["000000000000"], [])
        assert len(result) == 1
        assert result[0]["agentSpaceEntry"]["ruleType"] == "DEFAULT"
