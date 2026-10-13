# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Requirements E1 (failed role assumption) and E2 (no ListAccounts permission)."""

import pytest

from bedrock_permissions_audit.accounts import (
    AssumeRoleError,
    DiscoveryError,
    SessionFactory,
    discover,
)
from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.models import Account

CALLER = "111111111111"
SESSION_KEY_ID = "ASIA" + "EXAMPLE000000000"
IDENTITY = {
    "UserId": "AIDAEXAMPLE",
    "Account": CALLER,
    "Arn": f"arn:aws:iam::{CALLER}:user/auditor",
}


def stub_identity(session):
    session.stubber("sts").add_response("get_caller_identity", IDENTITY)


def org_accounts():
    return {
        "Accounts": [
            {"Id": CALLER, "Name": "management", "Status": "ACTIVE"},
            {"Id": "222222222222", "Name": "workloads", "Status": "ACTIVE"},
            {"Id": "333333333333", "Name": "closed", "Status": "SUSPENDED"},
        ]
    }


def test_org_mode_lists_only_active_accounts_and_flags_the_caller(stubbed_session):
    stub_identity(stubbed_session)
    stubbed_session.stubber("organizations").add_response("list_accounts", org_accounts())

    result = discover(Config(), stubbed_session)

    assert result.mode == "org"
    assert [a.account_id for a in result.accounts] == [CALLER, "222222222222"]
    assert [a.is_caller for a in result.accounts] == [True, False]
    assert result.accounts[1].name == "workloads"
    assert result.notice is None
    stubbed_session.assert_all_consumed()


def test_org_mode_paginates(stubbed_session):
    stub_identity(stubbed_session)
    orgs = stubbed_session.stubber("organizations")
    orgs.add_response(
        "list_accounts",
        {"Accounts": [{"Id": CALLER, "Status": "ACTIVE"}], "NextToken": "page2"},
    )
    orgs.add_response(
        "list_accounts",
        {"Accounts": [{"Id": "222222222222", "Status": "ACTIVE"}]},
        expected_params={"NextToken": "page2"},
    )

    result = discover(Config(), stubbed_session)

    assert [a.account_id for a in result.accounts] == [CALLER, "222222222222"]


def test_e2_access_denied_falls_back_to_single_account_with_notice(stubbed_session):
    stub_identity(stubbed_session)
    stubbed_session.stubber("organizations").add_client_error(
        "list_accounts", service_error_code="AccessDeniedException"
    )

    result = discover(Config(mode="auto"), stubbed_session)

    assert result.mode == "single"
    assert result.accounts == (Account(account_id=CALLER, is_caller=True),)
    assert "AccessDeniedException" in result.notice
    assert CALLER in result.notice


def test_account_not_in_an_organization_falls_back_in_auto_mode(stubbed_session):
    stub_identity(stubbed_session)
    stubbed_session.stubber("organizations").add_client_error(
        "list_accounts", service_error_code="AWSOrganizationsNotInUseException"
    )

    assert discover(Config(), stubbed_session).mode == "single"


def test_org_mode_does_not_fall_back(stubbed_session):
    stub_identity(stubbed_session)
    stubbed_session.stubber("organizations").add_client_error(
        "list_accounts", service_error_code="AccessDeniedException"
    )

    with pytest.raises(DiscoveryError, match="mode=org"):
        discover(Config(mode="org"), stubbed_session)


def test_single_mode_never_calls_organizations(stubbed_session):
    stub_identity(stubbed_session)

    result = discover(Config(mode="single"), stubbed_session)

    assert result.mode == "single"
    assert result.accounts[0].is_caller
    stubbed_session.assert_all_consumed()  # an unexpected organizations call would have raised


def test_unexpected_organizations_error_is_not_swallowed(stubbed_session):
    stub_identity(stubbed_session)
    stubbed_session.stubber("organizations").add_client_error(
        "list_accounts", service_error_code="ServiceException"
    )

    with pytest.raises(DiscoveryError, match="Cannot list organization accounts"):
        discover(Config(), stubbed_session)


def test_invalid_caller_credentials_raise_discovery_error(stubbed_session):
    stubbed_session.stubber("sts").add_client_error(
        "get_caller_identity", service_error_code="ExpiredToken"
    )

    with pytest.raises(DiscoveryError, match="ExpiredToken"):
        discover(Config(), stubbed_session)


def test_caller_outside_active_list_is_still_audited(stubbed_session):
    stub_identity(stubbed_session)
    stubbed_session.stubber("organizations").add_response(
        "list_accounts", {"Accounts": [{"Id": "222222222222", "Status": "ACTIVE"}]}
    )

    result = discover(Config(), stubbed_session)

    assert result.accounts[0] == Account(account_id=CALLER, is_caller=True)
    assert len(result.accounts) == 2


def make_factory(session, config=None):
    stub_identity(session)
    discovery = discover(Config(mode="single"), session)
    return SessionFactory(config or Config(), session, discovery)


def test_caller_account_reuses_the_base_session(stubbed_session):
    factory = make_factory(stubbed_session)
    assert factory.for_account(Account(CALLER, is_caller=True)) is stubbed_session


def test_member_account_is_assumed_with_configured_role(stubbed_session):
    factory = make_factory(stubbed_session, Config(role_name="BedrockAuditRole"))
    stubbed_session.stubber("sts").add_response(
        "assume_role",
        {
            "Credentials": {
                "AccessKeyId": SESSION_KEY_ID,
                "SecretAccessKey": "secret",  # noqa: S106
                "SessionToken": "token",  # noqa: S106
                "Expiration": "2030-01-01T00:00:00Z",
            }
        },
        expected_params={
            "RoleArn": "arn:aws:iam::222222222222:role/BedrockAuditRole",
            "RoleSessionName": "bedrock-permissions-audit",
            "DurationSeconds": 3600,
        },
    )

    member = factory.for_account(Account("222222222222"))

    assert member.get_credentials().access_key == SESSION_KEY_ID
    stubbed_session.assert_all_consumed()


def test_external_id_is_sent_when_configured(stubbed_session):
    factory = make_factory(stubbed_session, Config(external_id="ext-123"))
    stubbed_session.stubber("sts").add_response(
        "assume_role",
        {
            "Credentials": {
                "AccessKeyId": SESSION_KEY_ID,
                "SecretAccessKey": "s",  # noqa: S106
                "SessionToken": "t",  # noqa: S106
                "Expiration": "2030-01-01T00:00:00Z",
            }
        },
        expected_params={
            "RoleArn": "arn:aws:iam::222222222222:role/BedrockPermissionsAuditRole",
            "RoleSessionName": "bedrock-permissions-audit",
            "DurationSeconds": 3600,
            "ExternalId": "ext-123",
        },
    )

    factory.for_account(Account("222222222222"))
    stubbed_session.assert_all_consumed()


def test_e1_failed_assumption_raises_assume_role_error(stubbed_session):
    factory = make_factory(stubbed_session)
    stubbed_session.stubber("sts").add_client_error(
        "assume_role", service_error_code="AccessDenied", service_message="not authorized"
    )

    with pytest.raises(AssumeRoleError, match="AccessDenied") as info:
        factory.for_account(Account("222222222222"))
    assert "role/BedrockPermissionsAuditRole" in str(info.value)
    assert "infra/audit-role.yaml" in str(info.value), (
        "the default role failure should say how to fix it"
    )


def test_e27_a_failed_explicit_role_does_not_claim_the_default_is_missing(stubbed_session):
    factory = make_factory(stubbed_session, Config(role_name="OrganizationAccountAccessRole"))
    stubbed_session.stubber("sts").add_client_error(
        "assume_role", service_error_code="AccessDenied", service_message="not authorized"
    )

    with pytest.raises(AssumeRoleError) as info:
        factory.for_account(Account("222222222222"))

    assert "role/OrganizationAccountAccessRole" in str(info.value)
    assert "infra/audit-role.yaml" not in str(info.value)
