# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Requirement E9/E10 inputs: Amazon Bedrock and Claude Platform long-term API keys."""

from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError, ParamValidationError

from bedrock_permissions_audit.collectors.api_keys import (
    collect_bedrock_api_keys,
    collect_user_api_keys,
    is_access_denied,
    is_phantom_user,
    merge,
)

NOW = datetime(2026, 6, 1, tzinfo=UTC)


def item(
    user, cred_id, *, status="Active", created=None, expires=None, service="bedrock.amazonaws.com"
):
    data = {
        "UserName": user,
        "ServiceSpecificCredentialId": cred_id,
        "Status": status,
        "ServiceName": service,
        "CreateDate": created or NOW - timedelta(days=200),
    }
    if expires:
        data["ExpirationDate"] = expires
    return data


class FakeIam:
    def __init__(self, pages=None, error=None, per_user=None):
        self.pages = list(pages or [])
        self.error = error
        self.per_user = per_user or {}
        self.calls = []

    def list_service_specific_credentials(self, **params):
        self.calls.append(params)
        if self.error:
            raise self.error
        if "UserName" in params:
            result = self.per_user[params["UserName"]]
            if isinstance(result, Exception):
                raise result
            return {"ServiceSpecificCredentials": result}
        return self.pages.pop(0)


def client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "ListServiceSpecificCredentials")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("BedrockAPIKey-ab12", True),
        ("AeaApiKey-ab12", True),
        ("alice", False),
        ("bedrockapikey-ab12", False),
        ("my-BedrockAPIKey-ab12", False),
    ],
)
def test_phantom_prefixes(name, expected):
    assert is_phantom_user(name) is expected


def test_lists_account_wide_and_groups_by_user():
    iam = FakeIam(
        pages=[
            {
                "ServiceSpecificCredentials": [
                    item("BedrockAPIKey-ab12", "ID1"),
                    item("alice", "ID2"),
                ]
            }
        ]
    )

    keys, warnings = collect_bedrock_api_keys(iam, NOW)

    assert warnings == []
    assert iam.calls == [{"ServiceName": "bedrock.amazonaws.com", "AllUsers": True}]
    assert set(keys) == {"BedrockAPIKey-ab12", "alice"}  # not only phantom users
    key = keys["alice"][0]
    assert key.kind == "bedrock_api_key"
    assert key.key_id == "ID2"
    assert key.active is True
    assert key.age_days == 200
    assert key.last_used_known is False


def test_follows_the_marker_across_pages():
    iam = FakeIam(
        pages=[
            {
                "ServiceSpecificCredentials": [item("a", "ID1")],
                "IsTruncated": True,
                "Marker": "m1",
            },
            {"ServiceSpecificCredentials": [item("b", "ID2")], "IsTruncated": False},
        ]
    )

    keys, _ = collect_bedrock_api_keys(iam, NOW)

    assert set(keys) == {"a", "b"}
    assert iam.calls[1]["Marker"] == "m1"


def test_inactive_and_expired_keys_are_not_active():
    iam = FakeIam(
        pages=[
            {
                "ServiceSpecificCredentials": [
                    item("a", "ID1", status="Inactive"),
                    item("b", "ID2", expires=NOW - timedelta(days=1)),
                    item("c", "ID3", expires=NOW + timedelta(days=30)),
                ]
            }
        ]
    )

    keys, _ = collect_bedrock_api_keys(iam, NOW)

    assert keys["a"][0].active is False
    assert keys["b"][0].active is False  # past its expiry date
    assert keys["c"][0].active is True
    assert keys["c"][0].expires == NOW + timedelta(days=30)


def test_missing_permission_fails_loudly():
    with pytest.raises(ClientError):
        collect_bedrock_api_keys(FakeIam(error=client_error("AccessDenied")), NOW)


def test_old_boto3_without_all_users_warns_instead_of_crashing():
    iam = FakeIam(error=ParamValidationError(report="Unknown parameter AllUsers"))

    keys, warnings = collect_bedrock_api_keys(iam, NOW)

    assert keys == {}
    assert "upgrade boto3" in warnings[0]


def test_unexpected_service_error_warns():
    keys, warnings = collect_bedrock_api_keys(FakeIam(error=client_error("ServiceFailure")), NOW)
    assert keys == {}
    assert "ServiceFailure" in warnings[0]


def test_claude_platform_keys_are_found_per_user():
    iam = FakeIam(
        per_user={
            "AeaApiKey-zz99": [
                item("AeaApiKey-zz99", "CID1", service="claude.example.invalid"),
            ],
            "AeaApiKey-gone": client_error("NoSuchEntity"),
        }
    )

    keys = collect_user_api_keys(iam, ["AeaApiKey-zz99", "AeaApiKey-gone"], NOW)

    assert set(keys) == {"AeaApiKey-zz99"}
    assert keys["AeaApiKey-zz99"][0].kind == "claude_api_key"


def test_unrelated_credentials_on_ordinary_users_are_ignored():
    iam = FakeIam(per_user={"alice": [item("alice", "CC1", service="codecommit.amazonaws.com")]})
    assert collect_user_api_keys(iam, ["alice"], NOW) == {}


def test_merge_deduplicates_by_credential_id():
    first, _ = collect_bedrock_api_keys(
        FakeIam(pages=[{"ServiceSpecificCredentials": [item("a", "ID1")]}]), NOW
    )
    second, _ = collect_bedrock_api_keys(
        FakeIam(pages=[{"ServiceSpecificCredentials": [item("a", "ID1"), item("a", "ID2")]}]),
        NOW,
    )

    merged = merge(first, second)

    assert [c.key_id for c in merged["a"]] == ["ID1", "ID2"]


@pytest.mark.parametrize("code", ["AccessDenied", "AccessDeniedException", "UnauthorizedOperation"])
def test_access_denied_codes_are_recognised(code):
    assert is_access_denied(client_error(code))


@pytest.mark.parametrize("code", ["Throttling", "ServiceFailure", "NoSuchEntity"])
def test_other_errors_are_not_access_denied(code):
    assert not is_access_denied(client_error(code))
