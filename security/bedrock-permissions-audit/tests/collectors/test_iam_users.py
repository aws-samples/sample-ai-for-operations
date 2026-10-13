# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import json
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from bedrock_permissions_audit.collectors.credential_report import (
    ROOT_USER,
    ReportKey,
    ReportRow,
    fetch_credential_report,
)
from bedrock_permissions_audit.collectors.iam_users import collect_principals
from bedrock_permissions_audit.models import Credential

ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
READ_ONLY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
ACCOUNT = "123456789012"


@pytest.fixture
def iam():
    # Load the AWS managed policies so tests can attach AdministratorAccess and friends.
    with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
        yield boto3.client("iam", region_name="us-east-1")


def now_plus(days):
    return datetime.now(UTC) + timedelta(days=days)


def collect(iam, *, api_keys=None, report=None, now=None):
    return collect_principals(
        iam, ACCOUNT, report if report is not None else {}, api_keys or {}, now or now_plus(0)
    )


class ScriptedLastUsed:
    """Delegates to a real client but scripts GetAccessKeyLastUsed, which moto cannot set."""

    def __init__(self, client, last_used):
        self._client = client
        self._last_used = last_used

    def __getattr__(self, name):
        return getattr(self._client, name)

    def get_access_key_last_used(self, AccessKeyId):  # noqa: N803 - mirrors the boto3 signature
        value = self._last_used.get(AccessKeyId)
        if value is None:
            return {"AccessKeyLastUsed": {"Region": "N/A", "ServiceName": "N/A"}}
        return {"AccessKeyLastUsed": value}


def test_user_with_key_becomes_a_principal_with_age(iam):
    iam.create_user(UserName="alice")
    key = iam.create_access_key(UserName="alice")["AccessKey"]

    principals, warnings = collect(iam, now=now_plus(200))

    assert warnings == []
    (alice,) = principals
    assert alice.name == "alice"
    assert alice.arn == f"arn:aws:iam::{ACCOUNT}:user/alice"
    (credential,) = alice.access_keys
    assert credential.kind == "access_key"
    assert credential.key_id == key["AccessKeyId"]
    assert credential.active is True
    assert credential.age_days == 200
    assert credential.never_used is True
    assert credential.last_used_region is None


def test_last_used_date_and_region_come_from_get_access_key_last_used(iam):
    iam.create_user(UserName="alice")
    key_id = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    used = datetime(2026, 1, 1, tzinfo=UTC)
    scripted = ScriptedLastUsed(
        iam, {key_id: {"LastUsedDate": used, "Region": "eu-west-1", "ServiceName": "s3"}}
    )

    (alice,), _ = collect_principals(scripted, ACCOUNT, {}, {}, datetime(2026, 4, 11, tzinfo=UTC))

    credential = alice.access_keys[0]
    assert credential.last_used == used
    assert credential.last_used_region == "eu-west-1"
    assert credential.unused_days == 100
    assert credential.never_used is False
    assert credential.is_dormant(90) is True
    assert credential.is_dormant(120) is False


def test_inactive_key_is_kept_and_marked_inactive(iam):
    iam.create_user(UserName="alice")
    key_id = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="alice", AccessKeyId=key_id, Status="Inactive")

    (alice,), _ = collect(iam)

    assert alice.access_keys[0].active is False


def test_console_only_user_is_not_in_scope(iam):
    iam.create_user(UserName="console-only")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")

    principals, _ = collect(iam)

    assert [p.name for p in principals] == ["alice"]


def test_user_with_two_keys_has_both(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    iam.create_access_key(UserName="alice")

    (alice,), _ = collect(iam)

    assert len(alice.access_keys) == 2
    assert len({c.key_id for c in alice.access_keys}) == 2


def test_e10_orphaned_phantom_user_is_kept_without_credentials(iam):
    iam.create_user(UserName="BedrockAPIKey-ab12")
    iam.attach_user_policy(UserName="BedrockAPIKey-ab12", PolicyArn=ADMIN)

    (phantom,), _ = collect(iam)

    assert phantom.is_phantom is True
    assert phantom.credentials == ()
    assert phantom.attached_policy_arns == (ADMIN,)


def test_e9_user_with_only_an_api_key_is_included(iam):
    iam.create_user(UserName="BedrockAPIKey-ab12")
    api_key = Credential(
        kind="bedrock_api_key", key_id="ID1", active=True, age_days=10, last_used_known=False
    )

    (phantom,), _ = collect(iam, api_keys={"BedrockAPIKey-ab12": (api_key,)})

    assert phantom.access_keys == ()
    assert phantom.api_keys == (api_key,)
    assert phantom.credentials == (api_key,)


def test_ordinary_user_holding_an_api_key_is_included_but_not_phantom(iam):
    iam.create_user(UserName="alice")
    api_key = Credential(kind="bedrock_api_key", key_id="ID1", active=True, last_used_known=False)

    (alice,), _ = collect(iam, api_keys={"alice": (api_key,)})

    assert alice.is_phantom is False
    assert alice.api_keys == (api_key,)


def test_direct_and_group_policies_are_merged_and_deduplicated(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn=READ_ONLY)
    for group in ("devs", "ops"):
        iam.create_group(GroupName=group)
        iam.add_user_to_group(GroupName=group, UserName="alice")
        iam.attach_group_policy(GroupName=group, PolicyArn=ADMIN)

    (alice,), _ = collect(iam)

    assert alice.attached_policy_arns == (READ_ONLY, ADMIN)


def enable_mfa(iam, user_name):
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName=user_name)["VirtualMFADevice"]
    iam.enable_mfa_device(
        UserName=user_name,
        SerialNumber=device["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )


def test_mfa_is_read_from_the_user_not_from_the_credential_report(iam):
    """Regression, found on a real account: IAM serves a credential report up to four hours old,
    so a user created or changed since then is missing from it. Taking MFA from the report showed
    a user who does have MFA as having none."""
    iam.create_user(UserName="alice")
    iam.create_user(UserName="bob")
    iam.create_access_key(UserName="alice")
    iam.create_access_key(UserName="bob")
    enable_mfa(iam, "alice")
    stale_report = {}  # neither user is in the report yet

    principals, _ = collect(iam, report=stale_report)

    by_name = {p.name: p for p in principals}
    assert by_name["alice"].mfa_active is True
    assert by_name["bob"].mfa_active is False


def test_a_report_that_disagrees_with_the_user_is_ignored_for_mfa(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    report = {"alice": ReportRow("alice", "arn", True, ())}  # claims MFA; the user has none

    (alice,), _ = collect(iam, report=report)

    assert alice.mfa_active is False


def test_works_with_a_real_generated_report(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    report = fetch_credential_report(iam, sleep=lambda s: None)

    (alice,), _ = collect(iam, report=report)

    assert alice.mfa_active is False


def test_root_access_key_is_reported_from_the_credential_report():
    now = datetime(2026, 6, 1, tzinfo=UTC)
    row = ReportRow(
        user=ROOT_USER,
        arn=f"arn:aws:iam::{ACCOUNT}:root",
        mfa_active=True,
        keys=(
            ReportKey(1, True, datetime(2020, 6, 1, tzinfo=UTC), None, None),
            ReportKey(2, False, None, None, None),
        ),
    )
    with mock_aws():
        principals, _ = collect_principals(
            boto3.client("iam", region_name="us-east-1"), ACCOUNT, {ROOT_USER: row}, {}, now
        )

    (root,) = principals
    assert root.is_root is True
    assert root.name == ROOT_USER
    assert root.mfa_active is True
    (credential,) = root.access_keys
    assert credential.kind == "root_access_key"
    assert credential.id_masked == "root-access-key-1"  # a label, so it is not masked
    assert credential.age_days == 2191
    assert credential.never_used is True


def test_root_without_an_access_key_is_not_a_principal():
    row = ReportRow(ROOT_USER, "arn", False, (ReportKey(1, False, None, None, None),) * 2)
    with mock_aws():
        principals, _ = collect_principals(
            boto3.client("iam", region_name="us-east-1"),
            ACCOUNT,
            {ROOT_USER: row},
            {},
            now_plus(0),
        )
    assert principals == []


def test_root_comes_first(iam):
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    row = ReportRow(
        ROOT_USER, "arn", False, (ReportKey(1, True, datetime(2020, 1, 1, tzinfo=UTC), None, None),)
    )

    principals, _ = collect(iam, report={ROOT_USER: row})

    assert [p.name for p in principals] == [ROOT_USER, "alice"]


class VanishingUser:
    """A user deleted between ListUsers and ListAccessKeys."""

    def __init__(self, client, gone):
        self._client = client
        self._gone = gone

    def __getattr__(self, name):
        return getattr(self._client, name)

    def get_paginator(self, name):
        real = self._client.get_paginator(name)
        if name != "list_access_keys":
            return real
        gone = self._gone

        class Paginator:
            def paginate(self, **kwargs):
                if kwargs["UserName"] == gone:
                    raise ClientError(
                        {"Error": {"Code": "NoSuchEntity", "Message": "gone"}}, "ListAccessKeys"
                    )
                return real.paginate(**kwargs)

        return Paginator()


def test_user_deleted_mid_scan_is_skipped_with_a_warning(iam):
    for name in ("alice", "bob"):
        iam.create_user(UserName=name)
        iam.create_access_key(UserName=name)

    principals, warnings = collect_principals(
        VanishingUser(iam, "bob"), ACCOUNT, {}, {}, now_plus(0)
    )

    assert [p.name for p in principals] == ["alice"]
    assert warnings == ["User bob was deleted during the scan and was skipped."]


def test_other_errors_propagate_so_the_account_is_marked_failed(iam):
    iam.create_user(UserName="alice")

    class Denied(VanishingUser):
        def get_paginator(self, name):
            if name == "list_access_keys":
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListAccessKeys"
                )
            return self._client.get_paginator(name)

    with pytest.raises(ClientError, match="AccessDenied"):
        collect_principals(Denied(iam, "x"), ACCOUNT, {}, {}, now_plus(0))


def test_policy_document_content_is_never_read(iam):
    """Only ARNs are collected, never policy documents (design: output holds names, not JSON)."""
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")
    policy = iam.create_policy(
        PolicyName="Custom",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}],
            }
        ),
    )["Policy"]
    iam.attach_user_policy(UserName="alice", PolicyArn=policy["Arn"])

    (alice,), _ = collect(iam)

    assert alice.attached_policy_arns == (policy["Arn"],)
