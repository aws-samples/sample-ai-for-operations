# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The whole per-account pipeline (collect, evaluate, score) against a moto account.

moto serves IAM users, keys, groups and the credential report. Two things moto cannot do are
replaced: the policy simulator (an IAM-rules fake) and account-wide API key listing."""

from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.exceptions import ParamValidationError
from moto import mock_aws

from bedrock_permissions_audit.accounts import SessionFactory, discover
from bedrock_permissions_audit.audit import audit_account, make_worker
from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.evaluator import Evaluation, SimulatorEvaluator
from bedrock_permissions_audit.models import Account, Principal, Tier

from ..evaluator.fake_simulator import FakeIam, allow
from .dsl import ADMIN

ACCOUNT = Account(account_id="123456789012", name="workloads", is_caller=True)
NOW = datetime.now(UTC) + timedelta(days=200)  # makes every key created "today" 200 days old


class IamWithScriptedApiKeys:
    """A moto IAM client, except account-wide API key listing returns scripted data."""

    def __init__(self, client, api_keys):
        self._client = client
        self._api_keys = api_keys

    def __getattr__(self, name):
        return getattr(self._client, name)

    def list_service_specific_credentials(self, **params):
        if "UserName" in params:
            return {"ServiceSpecificCredentials": []}
        return {"ServiceSpecificCredentials": self._api_keys}


class Session:
    def __init__(self, client):
        self._client = client

    def client(self, name, config=None):
        assert name == "iam"
        return self._client


class PerUserEvaluator:
    """Route each principal to its own fake policy set, like the real simulator would."""

    def __init__(self, policies):
        self._policies = policies

    def evaluate(self, principal: Principal) -> Evaluation:
        iam = FakeIam(self._policies.get(principal.name, []))
        return SimulatorEvaluator(iam, Config()).evaluate(principal)


@pytest.fixture
def account():
    with mock_aws(config={"iam": {"load_aws_managed_policies": True}}):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_group(GroupName="admins")
        iam.attach_group_policy(GroupName="admins", PolicyArn=ADMIN)

        iam.create_user(UserName="admin-alice")
        iam.add_user_to_group(GroupName="admins", UserName="admin-alice")
        iam.create_access_key(UserName="admin-alice")

        iam.create_user(UserName="ci-bot")
        iam.create_access_key(UserName="ci-bot")

        iam.create_user(UserName="s3-reader")
        iam.create_access_key(UserName="s3-reader")

        iam.create_user(UserName="console-only")

        iam.create_user(UserName="BedrockAPIKey-abc1")
        iam.create_user(UserName="BedrockAPIKey-gone")  # orphaned: no credential of any kind
        yield iam


API_KEYS = [
    {
        "UserName": "BedrockAPIKey-abc1",
        "ServiceSpecificCredentialId": "ABCD1234ABCD1234ABCD1",
        "ServiceName": "bedrock.amazonaws.com",
        "Status": "Active",
        "CreateDate": datetime.now(UTC),
    }
]
POLICIES = {
    "admin-alice": [allow(["*"])],
    "ci-bot": [allow(["bedrock:InvokeModel"])],
    "s3-reader": [allow(["s3:GetObject"])],
    # Narrow on purpose: with bedrock:* the canary rule makes it Critical (tested separately).
    "BedrockAPIKey-abc1": [allow(["bedrock:CallWithBearerToken", "bedrock:InvokeModel"])],
    "BedrockAPIKey-gone": [allow(["bedrock:*"])],
}


def run(account_iam, config=None):
    session = Session(IamWithScriptedApiKeys(account_iam, API_KEYS))
    return audit_account(
        ACCOUNT, session, config or Config(), NOW, lambda iam, cfg: PerUserEvaluator(POLICIES)
    )


def by_name(result):
    return {f.principal_name: f for f in result.findings}


def test_end_to_end_tiers(account):
    result = run(account)

    assert result.status == "ok"
    findings = by_name(result)
    assert findings["admin-alice"].tier is Tier.CRITICAL
    assert findings["admin-alice"].admin_policies == (ADMIN,)
    assert findings["ci-bot"].tier is Tier.HIGH  # 200 days old, never used, no MFA
    assert findings["s3-reader"].tier is Tier.INFO
    assert findings["BedrockAPIKey-abc1"].tier is Tier.HIGH
    assert findings["BedrockAPIKey-abc1"].credential.kind == "bedrock_api_key"
    assert findings["BedrockAPIKey-gone"].orphaned is True
    assert findings["BedrockAPIKey-gone"].tier is Tier.MEDIUM


def test_api_key_user_with_full_bedrock_access_is_critical(account):
    """Console-created Bedrock API keys carry a policy that allows far more than invocation."""
    policies = {**POLICIES, "BedrockAPIKey-abc1": [allow(["bedrock:*", "bedrock-mantle:*"])]}
    session = Session(IamWithScriptedApiKeys(account, API_KEYS))

    result = audit_account(
        ACCOUNT, session, Config(), NOW, lambda iam, cfg: PerUserEvaluator(policies)
    )

    finding = by_name(result)["BedrockAPIKey-abc1"]
    assert finding.tier is Tier.CRITICAL
    assert any("bedrock:*" in reason for reason in finding.tier_reasons)


def test_console_only_user_is_not_a_principal(account):
    result = run(account)

    assert "console-only" not in by_name(result)
    assert result.principals_evaluated == 5


def test_findings_never_carry_a_full_key_id_in_text_fields(account):
    result = run(account)
    keys = {f.credential.key_id for f in result.findings if f.credential}

    for finding in result.findings:
        text = " ".join([finding.recommended_action, *finding.tier_reasons, *finding.warnings])
        assert not any(key in text for key in keys)


class IamWithoutAllUsers(IamWithScriptedApiKeys):
    """An older boto3: the account-wide call is rejected, the per-user call works."""

    def list_service_specific_credentials(self, **params):
        if "AllUsers" in params:
            raise ParamValidationError(report='Unknown parameter in input: "AllUsers"')
        keys = [k for k in self._api_keys if k["UserName"] == params.get("UserName")]
        return {"ServiceSpecificCredentials": keys}


def test_old_boto3_still_finds_keys_on_api_key_users_and_says_what_it_could_not_cover(account):
    """Regression: the fallback must really query BedrockAPIKey-* users, as its warning claims."""
    session = Session(IamWithoutAllUsers(account, API_KEYS))

    result = audit_account(
        ACCOUNT, session, Config(), NOW, lambda iam, cfg: PerUserEvaluator(POLICIES)
    )

    finding = by_name(result)["BedrockAPIKey-abc1"]
    assert finding.credential.kind == "bedrock_api_key"
    assert finding.tier is Tier.HIGH
    assert any("other user may be missing" in warning for warning in result.warnings)


def test_make_worker_assumes_nothing_for_the_caller_account(account):
    class FakeSts:
        def get_caller_identity(self):
            return {
                "Account": ACCOUNT.account_id,
                "Arn": f"arn:aws:iam::{ACCOUNT.account_id}:user/a",
            }

    class BaseSession:
        def client(self, name, config=None):
            return FakeSts() if name == "sts" else IamWithScriptedApiKeys(account, API_KEYS)

    base = BaseSession()
    discovery = discover(Config(mode="single"), base)
    worker = make_worker(
        Config(),
        SessionFactory(Config(), base, discovery),
        NOW,
        lambda iam, cfg: PerUserEvaluator(POLICIES),
    )

    result = worker(ACCOUNT)

    assert result.status == "ok"
    assert len(result.findings) == 5


def test_a_permission_error_in_the_simulator_fails_the_account_loudly(account):
    def failing(iam, cfg):
        return SimulatorEvaluator(FakeIam([], raise_error="AccessDenied"), cfg)

    session = Session(IamWithScriptedApiKeys(account, API_KEYS))

    with pytest.raises(Exception, match="AccessDenied"):
        audit_account(ACCOUNT, session, Config(), NOW, failing)
