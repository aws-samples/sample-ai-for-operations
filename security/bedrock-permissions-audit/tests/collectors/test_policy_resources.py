# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Finding the Amazon Bedrock resources a user's own policies name."""

import pytest
from botocore.exceptions import ClientError

from bedrock_permissions_audit.collectors.policy_resources import (
    WILDCARD_TOKEN,
    PolicyResourceReader,
    extract_bedrock_resources,
    iam_matches,
    is_bedrock_arn,
    probe_arns,
)
from bedrock_permissions_audit.config import DEFAULT_INVOKE_ACTIONS
from bedrock_permissions_audit.models import Principal

TITAN = "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1"
INVOKE = DEFAULT_INVOKE_ACTIONS
ACCOUNT = "123456789012"
REGIONS = ("us-east-1", "us-west-2", "eu-west-1")


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource, **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


class TestIamMatches:
    @pytest.mark.parametrize(
        ("pattern", "value", "expected"),
        [
            ("bedrock:*", "bedrock:InvokeModel", True),
            ("bedrock:Invoke*", "bedrock:InvokeModel", True),
            ("bedrock:Invoke*", "bedrock:Converse", False),
            ("*", "bedrock:InvokeModel", True),
            (
                "bedrock:Converse?tream",
                "bedrock:ConverseStream",
                True,
            ),  # ? is exactly one character
            (
                "bedrock:Converse?",
                "bedrock:Converse",
                False,
            ),  # ... so it needs a character to match
            ("bedrock:Converse?", "bedrock:ConverseStream", False),
            ("a.b", "axb", False),  # a dot is a literal, not a regex wildcard
        ],
    )
    def test_wildcards(self, pattern, value, expected):
        assert iam_matches(pattern, value) is expected

    def test_action_names_match_case_insensitively(self):
        assert iam_matches("BEDROCK:invokemodel", "bedrock:InvokeModel", ignore_case=True)


class TestExtract:
    def test_a_named_model_is_returned(self):
        found = extract_bedrock_resources(doc(allow("bedrock:InvokeModel", TITAN)), INVOKE)
        assert found == [TITAN]

    def test_a_list_of_resources_and_actions(self):
        document = doc(allow(["bedrock:InvokeModel", "s3:GetObject"], [TITAN, "arn:aws:s3:::b"]))
        assert extract_bedrock_resources(document, INVOKE) == [TITAN]

    @pytest.mark.parametrize("action", ["bedrock:*", "*", "bedrock:Invoke*", "bedrock:Converse*"])
    def test_wildcard_actions_that_cover_invoke_count(self, action):
        assert extract_bedrock_resources(doc(allow(action, TITAN)), INVOKE) == [TITAN]

    def test_actions_that_do_not_cover_invoke_are_ignored(self):
        document = doc(allow(["bedrock:ListFoundationModels", "bedrock:GetGuardrail"], TITAN))
        assert extract_bedrock_resources(document, INVOKE) == []

    def test_deny_statements_are_ignored(self):
        document = doc({"Effect": "Deny", "Action": "bedrock:*", "Resource": TITAN})
        assert extract_bedrock_resources(document, INVOKE) == []

    def test_not_resource_statements_are_ignored(self):
        document = doc(
            {"Effect": "Allow", "Action": "bedrock:*", "NotResource": TITAN},
        )
        assert extract_bedrock_resources(document, INVOKE) == []

    def test_not_action_statements_may_cover_invoke(self):
        document = doc({"Effect": "Allow", "NotAction": "s3:*", "Resource": TITAN})
        assert extract_bedrock_resources(document, INVOKE) == [TITAN]

    def test_star_and_non_bedrock_resources_are_skipped(self):
        document = doc(allow("bedrock:InvokeModel", ["*", "arn:aws:s3:::bucket/*"]))
        assert extract_bedrock_resources(document, INVOKE) == []

    def test_a_single_statement_object_is_accepted(self):
        document = {"Statement": allow("bedrock:InvokeModel", TITAN)}
        assert extract_bedrock_resources(document, INVOKE) == [TITAN]

    def test_duplicates_collapse_in_order(self):
        other = "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0"
        document = doc(allow("bedrock:*", [TITAN, other]), allow("bedrock:*", TITAN))
        assert extract_bedrock_resources(document, INVOKE) == [TITAN, other]

    def test_a_policy_with_no_statements(self):
        assert extract_bedrock_resources({"Version": "2012-10-17"}, INVOKE) == []

    @pytest.mark.parametrize(
        ("resource", "expected"),
        [
            (TITAN, True),
            ("arn:aws:bedrock:*:*:*", True),
            ("arn:aws:bedrock-mantle:us-east-1:123456789012:thing/x", True),
            ("arn:aws:s3:::bucket", False),
            ("*", False),
            ("bedrock", False),
        ],
    )
    def test_is_bedrock_arn(self, resource, expected):
        assert is_bedrock_arn(resource) is expected


class TestProbeArns:
    def test_an_explicit_model_is_returned_unchanged(self):
        assert probe_arns(TITAN, REGIONS, ACCOUNT) == [TITAN]

    def test_a_wildcard_region_expands_to_the_configured_regions(self):
        pattern = "arn:aws:bedrock:*::foundation-model/amazon.titan-text-lite-v1"

        probes = probe_arns(pattern, REGIONS, ACCOUNT)

        assert probes == [
            f"arn:aws:bedrock:{region}::foundation-model/amazon.titan-text-lite-v1"
            for region in REGIONS
        ]

    def test_a_partial_region_wildcard_expands_only_to_matches(self):
        pattern = "arn:aws:bedrock:us-*::foundation-model/amazon.titan-text-lite-v1"

        assert [p.split(":")[3] for p in probe_arns(pattern, REGIONS, ACCOUNT)] == [
            "us-east-1",
            "us-west-2",
        ]

    def test_a_wildcard_in_the_model_becomes_a_token_that_matches_its_own_pattern(self):
        pattern = "arn:aws:bedrock:us-east-1::foundation-model/ai21.*"

        (probe,) = probe_arns(pattern, REGIONS, ACCOUNT)

        assert probe == f"arn:aws:bedrock:us-east-1::foundation-model/ai21.{WILDCARD_TOKEN}"
        assert iam_matches(pattern, probe)

    @pytest.mark.parametrize(
        "pattern",
        [
            "arn:aws:bedrock:us-east-1::foundation-model/*titan*",
            "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-*-v1:0",
            "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-?ite-v1",
            "arn:aws:bedrock:*:*:inference-profile/*",
            "arn:aws:bedrock:*::foundation-model/*",
        ],
    )
    def test_every_probe_matches_the_pattern_it_came_from(self, pattern):
        probes = probe_arns(pattern, REGIONS, ACCOUNT)

        assert probes
        assert all(iam_matches(pattern, probe) for probe in probes)

    def test_a_wildcard_account_becomes_the_principals_account(self):
        pattern = "arn:aws:bedrock:us-east-1:*:inference-profile/us.anthropic.claude-3-haiku-v1:0"

        (probe,) = probe_arns(pattern, REGIONS, ACCOUNT)

        assert probe.split(":")[4] == ACCOUNT

    def test_a_wildcard_partition_becomes_aws(self):
        pattern = "arn:*:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1"

        (probe,) = probe_arns(pattern, REGIONS, ACCOUNT)

        assert probe.startswith("arn:aws:bedrock:")

    @pytest.mark.parametrize(
        "pattern", ["arn:aws:bedrock:*:*:*", "arn:aws:bedrock:us-east-1::*/x", "not-an-arn"]
    )
    def test_patterns_that_cannot_become_an_arn_give_no_probes(self, pattern):
        """Left to the bundled sample, not guessed at."""
        assert probe_arns(pattern, REGIONS, ACCOUNT) == []


class FakeIam:
    """Serves a user's policies and counts the reads, so caching can be checked."""

    def __init__(self, inline=None, managed=None, group_inline=None):
        self.inline = inline or {}
        self.managed = managed or {}
        self.group_inline = group_inline or {}
        self.reads = []

    def get_paginator(self, name):
        names = {
            "list_user_policies": list(self.inline),
            "list_group_policies": list(self.group_inline.get("_names", [])),
        }
        page = {"PolicyNames": names[name]}

        class Paginator:
            @staticmethod
            def paginate(**params):
                return iter([page])

        self.reads.append((name, name))
        return Paginator()

    def get_user_policy(self, UserName, PolicyName):  # noqa: N803
        self.reads.append(("get_user_policy", PolicyName))
        return {"PolicyDocument": self.inline[PolicyName]}

    def get_group_policy(self, GroupName, PolicyName):  # noqa: N803
        self.reads.append(("get_group_policy", GroupName))
        return {"PolicyDocument": self.group_inline[GroupName][PolicyName]}

    def get_policy(self, PolicyArn):  # noqa: N803
        self.reads.append(("get_policy", PolicyArn))
        if PolicyArn not in self.managed:
            raise ClientError({"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "GetPolicy")
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):  # noqa: N803
        self.reads.append(("get_policy_version", PolicyArn))
        return {"PolicyVersion": {"Document": self.managed[PolicyArn]}}


def principal(**overrides):
    values = {"account_id": ACCOUNT, "name": "alice", "arn": f"arn:aws:iam::{ACCOUNT}:user/alice"}
    values.update(overrides)
    return Principal(**values)


class TestReader:
    def test_inline_policy(self):
        iam = FakeIam(inline={"p": doc(allow("bedrock:InvokeModel", TITAN))})

        assert PolicyResourceReader(iam, INVOKE).resources_for(principal()) == (TITAN,)

    def test_attached_managed_policy(self):
        arn = "arn:aws:iam::123456789012:policy/Titan"
        iam = FakeIam(managed={arn: doc(allow("bedrock:InvokeModel", TITAN))})

        found = PolicyResourceReader(iam, INVOKE).resources_for(
            principal(attached_policy_arns=(arn,))
        )

        assert found == (TITAN,)

    def test_group_inline_policy(self):
        iam = FakeIam(
            group_inline={"_names": ["g"], "devs": {"g": doc(allow("bedrock:Converse", TITAN))}}
        )

        found = PolicyResourceReader(iam, INVOKE).resources_for(principal(groups=("devs",)))

        assert found == (TITAN,)

    def test_all_three_sources_are_merged_without_duplicates(self):
        other = "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0"
        arn = "arn:aws:iam::123456789012:policy/P"
        iam = FakeIam(
            inline={"p": doc(allow("bedrock:*", TITAN))},
            managed={arn: doc(allow("bedrock:*", [TITAN, other]))},
        )

        found = PolicyResourceReader(iam, INVOKE).resources_for(
            principal(attached_policy_arns=(arn,))
        )

        assert found == (TITAN, other)

    def test_a_managed_policy_shared_by_many_users_is_read_once(self):
        arn = "arn:aws:iam::123456789012:policy/Shared"
        iam = FakeIam(managed={arn: doc(allow("bedrock:*", TITAN))})
        reader = PolicyResourceReader(iam, INVOKE)

        for name in ("a", "b", "c"):
            reader.resources_for(principal(name=name, attached_policy_arns=(arn,)))

        assert [r for r in iam.reads if r[0] == "get_policy"] == [("get_policy", arn)]
        assert [r for r in iam.reads if r[0] == "get_policy_version"] == [
            ("get_policy_version", arn)
        ]

    def test_a_group_shared_by_many_users_is_read_once(self):
        iam = FakeIam(group_inline={"_names": ["g"], "devs": {"g": doc(allow("bedrock:*", TITAN))}})
        reader = PolicyResourceReader(iam, INVOKE)

        for name in ("a", "b"):
            reader.resources_for(principal(name=name, groups=("devs",)))

        assert [r for r in iam.reads if r[0] == "get_group_policy"] == [
            ("get_group_policy", "devs")
        ]

    def test_a_policy_deleted_mid_scan_is_skipped(self):
        gone = "arn:aws:iam::123456789012:policy/Gone"

        found = PolicyResourceReader(FakeIam(), INVOKE).resources_for(
            principal(attached_policy_arns=(gone,))
        )

        assert found == ()

    def test_other_errors_propagate_so_a_missing_permission_is_loud(self):
        class Denied(FakeIam):
            def get_policy(self, PolicyArn):  # noqa: N803
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetPolicy")

        with pytest.raises(ClientError, match="AccessDenied"):
            PolicyResourceReader(Denied(), INVOKE).resources_for(
                principal(attached_policy_arns=("arn:aws:iam::aws:policy/X",))
            )

    def test_a_user_with_no_policies_costs_one_listing(self):
        iam = FakeIam()

        assert PolicyResourceReader(iam, INVOKE).resources_for(principal()) == ()
        assert iam.reads == [("list_user_policies", "list_user_policies")]
