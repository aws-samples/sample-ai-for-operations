# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from datetime import UTC, datetime

import pytest

from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.models import Tier
from bedrock_permissions_audit.scoring.tiers import assign

from .factories import ADMIN, INVOKE, allowed, credential, finding

CONFIG = Config()  # dormant_days = 90


def tier(**overrides) -> Tier:
    return assign(finding(**overrides), CONFIG).tier


def test_healthy_broad_grant_is_medium():
    assert tier() is Tier.MEDIUM


def test_healthy_scoped_grant_is_low():
    assert tier(grant="scoped") is Tier.LOW


def test_cannot_invoke_is_info():
    assert tier(results=allowed("s3:GetObject"), grant="none") is Tier.INFO


class TestCritical:
    def test_active_root_key(self):
        result = assign(
            finding(is_root=True, credential=credential(kind="root_access_key")), CONFIG
        )
        assert result.tier is Tier.CRITICAL
        assert "root" in result.reasons[0].lower()

    def test_inactive_root_key_is_not_critical(self):
        root = finding(is_root=True, credential=credential(kind="root_access_key", active=False))
        assert assign(root, CONFIG).tier is Tier.INFO

    def test_admin_policy_with_invoke(self):
        assert tier(admin_policies=(ADMIN,)) is Tier.CRITICAL

    def test_all_canary_actions_mean_bedrock_star(self):
        result = assign(
            finding(results=allowed(INVOKE, *CONFIG.canary_actions), mfa_active=True), CONFIG
        )
        assert result.tier is Tier.CRITICAL
        assert any("bedrock:*" in reason for reason in result.reasons)

    @pytest.mark.parametrize("missing", range(6))
    def test_one_canary_action_missing_never_claims_bedrock_star(self, missing):
        """Granting five of the six unrelated management actions is not bedrock:*."""
        actions = [a for i, a in enumerate(CONFIG.canary_actions) if i != missing]
        result = assign(finding(results=allowed(INVOKE, *actions)), CONFIG)
        assert result.tier is Tier.MEDIUM
        assert not any("bedrock:*" in reason for reason in result.reasons)

    def test_a_single_canary_action_is_not_bedrock_star(self):
        """The reported bug: one allowed bedrock:DeleteCustomModel made a finding Critical."""
        result = assign(finding(results=allowed(INVOKE, "bedrock:DeleteCustomModel")), CONFIG)
        assert result.tier is Tier.MEDIUM

    def test_canary_actions_are_configurable_and_all_must_pass(self):
        config = Config(canary_actions=("bedrock:DeleteCustomModel", "bedrock:DeleteGuardrail"))
        both = finding(results=allowed(INVOKE, *config.canary_actions))
        one = finding(results=allowed(INVOKE, "bedrock:DeleteGuardrail"))
        assert assign(both, config).tier is Tier.CRITICAL
        assert assign(one, config).tier is Tier.MEDIUM

    def test_an_empty_canary_list_never_claims_bedrock_star(self):
        config = Config(canary_actions=())
        assert assign(finding(results=allowed(INVOKE, *CONFIG.canary_actions)), config).tier is (
            Tier.MEDIUM
        )

    @pytest.mark.parametrize(
        "action",
        [
            "aws-marketplace:Subscribe",
            "bedrock:CreateMarketplaceModelEndpoint",
            "iam:CreateServiceSpecificCredential",
        ],
    )
    def test_escalation_action_with_invoke(self, action):
        result = assign(finding(results=allowed(INVOKE, action)), CONFIG)
        assert result.tier is Tier.CRITICAL
        assert any(action in reason for reason in result.reasons)

    def test_admin_policy_without_invoke_is_not_critical(self):
        """An explicit deny leaves AdministratorAccess attached but unable to reach Bedrock."""
        assert tier(admin_policies=(ADMIN,), results=(), grant="none") is Tier.INFO

    def test_escalation_alone_without_invoke_is_not_critical(self):
        assert tier(results=allowed("aws-marketplace:Subscribe"), grant="none") is Tier.INFO

    def test_reasons_name_the_policy(self):
        result = assign(finding(admin_policies=(ADMIN,)), CONFIG)
        assert any("AdministratorAccess" in reason for reason in result.reasons)


class TestHigh:
    def test_never_used_key(self):
        result = assign(finding(credential=credential(unused_days=None, last_used=None)), CONFIG)
        assert result.tier is Tier.HIGH
        assert any("never been used" in reason for reason in result.reasons)

    @pytest.mark.parametrize(
        ("unused", "expected"), [(89, Tier.MEDIUM), (90, Tier.HIGH), (91, Tier.HIGH)]
    )
    def test_dormancy_threshold_is_inclusive(self, unused, expected):
        assert tier(credential=credential(unused_days=unused)) is expected

    @pytest.mark.parametrize(
        ("age", "expected"), [(89, Tier.MEDIUM), (90, Tier.HIGH), (400, Tier.HIGH)]
    )
    def test_age_threshold_is_inclusive(self, age, expected):
        assert tier(credential=credential(age_days=age)) is expected

    def test_no_mfa_on_an_access_key(self):
        result = assign(finding(mfa_active=False), CONFIG)
        assert result.tier is Tier.HIGH
        assert any("MFA" in reason for reason in result.reasons)

    def test_custom_threshold_changes_the_boundary(self):
        short = Config(dormant_days=30)
        key = credential(unused_days=45)
        assert assign(finding(credential=key), short).tier is Tier.HIGH
        assert assign(finding(credential=key), CONFIG).tier is Tier.MEDIUM

    def test_dormant_key_that_cannot_invoke_is_not_high(self):
        assert tier(credential=credential(unused_days=500), results=(), grant="none") is Tier.INFO


class TestApiKeys:
    def api_key(self, **overrides):
        values = {
            "kind": "bedrock_api_key",
            "key_id": "ABCD1234ABCD1234ABCD1",
            "unused_days": None,
            "last_used": None,
            "last_used_known": False,
            "age_days": 5,
        }
        values.update(overrides)
        return credential(**values)

    def test_e9_phantom_user_api_key_is_high(self):
        result = assign(
            finding(
                is_phantom=True,
                credential=self.api_key(),
                results=allowed("bedrock:CallWithBearerToken"),
            ),
            CONFIG,
        )
        assert result.tier is Tier.HIGH

    def test_unknown_last_use_is_not_treated_as_never_used(self):
        key = self.api_key()
        assert key.never_used is False
        assert key.is_dormant(90) is False

    def test_mfa_is_irrelevant_to_a_bearer_token(self):
        """No MFA must not push an API key to High on its own; a bearer token cannot use MFA."""
        result = assign(
            finding(
                credential=self.api_key(),
                mfa_active=False,
                results=allowed("bedrock:CallWithBearerToken"),
            ),
            CONFIG,
        )
        assert result.tier is Tier.MEDIUM

    def test_phantom_user_with_no_access_is_not_high(self):
        result = assign(
            finding(is_phantom=True, credential=self.api_key(), results=(), grant="none"),
            CONFIG,
        )
        assert result.tier is Tier.INFO

    def test_a_recent_api_key_is_never_described_as_in_use(self):
        """Regression, seen on a real account: IAM does not report API key use."""
        result = assign(
            finding(
                credential=self.api_key(),
                results=allowed("bedrock:CallWithBearerToken"),
            ),
            CONFIG,
        )
        assert result.tier is Tier.MEDIUM
        assert "in use" not in result.reasons[0]
        assert "does not report" in result.reasons[0]

    def test_an_access_key_in_use_is_described_as_in_use(self):
        assert "in use" in assign(finding(), CONFIG).reasons[0]

    def test_old_api_key_is_high(self):
        result = assign(
            finding(
                credential=self.api_key(age_days=120),
                results=allowed("bedrock:CallWithBearerToken"),
            ),
            CONFIG,
        )
        assert result.tier is Tier.HIGH


class TestOtherCases:
    def test_e10_orphaned_phantom_user_is_medium(self):
        assert (
            tier(orphaned=True, credential=None, is_phantom=True, results=(), grant="none")
            is Tier.MEDIUM
        )

    def test_unknown_evaluation_is_info_with_a_clear_reason(self):
        result = assign(finding(grant="unknown", results=()), CONFIG)
        assert result.tier is Tier.INFO
        assert "manually" in result.reasons[0]

    def test_scoped_grant_names_the_regions(self):
        result = assign(finding(grant="scoped", regions_allowed=("eu-west-1",)), CONFIG)
        assert "eu-west-1" in result.reasons[0]

    def test_custom_invoke_actions_are_respected(self):
        config = Config(invoke_actions=("bedrock:Converse",))
        assert assign(finding(results=allowed(INVOKE)), config).tier is Tier.INFO


class TestInactiveKeys:
    """Deactivating an access key does not invalidate its secret, so anyone who can call
    iam:UpdateAccessKey can re-enable it. An inactive key is rated as if it were active."""

    REENABLE = (
        "The key is inactive but its secret works again if anyone re-enables it with "
        "iam:UpdateAccessKey."
    )

    def inactive(self, **overrides):
        key = overrides.pop("credential", None) or credential(active=False)
        return finding(credential=key, **overrides)

    def test_admin_user_with_an_inactive_key_is_low_and_says_it_would_be_critical(self):
        """The reported case: AdministratorAccess, key deactivated and unused for 350 days."""
        key = credential(active=False, age_days=390, unused_days=350)
        result = assign(
            self.inactive(credential=key, mfa_active=False, admin_policies=(ADMIN,)), CONFIG
        )

        assert result.tier is Tier.LOW
        assert result.if_reactivated is Tier.CRITICAL
        assert result.reasons[0] == self.REENABLE
        assert result.reasons[1] == "If re-enabled it would rate Critical:"
        assert "Can invoke Amazon Bedrock models." in result.reasons[2:]
        assert any("AdministratorAccess" in reason for reason in result.reasons[2:])

    def test_inactive_dormant_broad_key_without_mfa_is_low_and_would_be_high(self):
        key = credential(active=False, age_days=163, unused_days=161)
        result = assign(self.inactive(credential=key, mfa_active=False), CONFIG)

        assert result.tier is Tier.LOW
        assert result.if_reactivated is Tier.HIGH
        assert result.reasons[:2] == (self.REENABLE, "If re-enabled it would rate High:")
        assert any("MFA" in reason for reason in result.reasons[2:])

    def test_inactive_key_with_no_amazon_bedrock_access_stays_info(self):
        result = assign(self.inactive(results=allowed("s3:GetObject"), grant="none"), CONFIG)

        assert result.tier is Tier.INFO
        assert result.if_reactivated is None

    def test_inactive_key_that_would_only_be_medium_stays_info(self):
        """Recent, in use, MFA on, broad: Medium if active, so not worth a default-visible row."""
        result = assign(self.inactive(), CONFIG)

        assert result.tier is Tier.INFO
        assert result.if_reactivated is None
        assert result.reasons == ("The credential is inactive or expired and cannot be used.",)

    def test_inactive_key_that_would_only_be_low_stays_info(self):
        assert assign(self.inactive(grant="scoped"), CONFIG).tier is Tier.INFO

    @staticmethod
    def api_key(**overrides):
        values = {
            "kind": "bedrock_api_key",
            "key_id": "ABCD1234ABCD1234ABCD1",
            "active": False,
            "unused_days": None,
            "last_used": None,
            "last_used_known": False,
            "age_days": 500,
        }
        values.update(overrides)
        return credential(**values)

    def api_key_finding(self, key, **overrides):
        values = {
            "credential": key,
            "is_phantom": True,
            "mfa_active": False,
            "admin_policies": (ADMIN,),
            "results": allowed("bedrock:CallWithBearerToken"),
        }
        values.update(overrides)
        return finding(**values)

    def test_expired_api_key_with_invoke_stays_info(self):
        """Expired credentials cannot be re-enabled, however much they could do."""
        expired = self.api_key(expires=datetime(2020, 1, 1, tzinfo=UTC), expired=True)

        result = assign(self.api_key_finding(expired), CONFIG)

        assert result.tier is Tier.INFO
        assert result.if_reactivated is None

    def test_inactive_api_key_that_would_be_critical_is_low(self):
        """Deactivated, not expired: iam:UpdateServiceSpecificCredential can switch it back on."""
        result = assign(self.api_key_finding(self.api_key()), CONFIG)

        assert result.tier is Tier.LOW
        assert result.if_reactivated is Tier.CRITICAL
        assert "iam:UpdateServiceSpecificCredential" in result.reasons[0]
        assert "iam:UpdateAccessKey" not in result.reasons[0]
        assert result.reasons[1] == "If re-enabled it would rate Critical:"

    def test_inactive_api_key_that_would_be_high_is_low(self):
        key = self.api_key(expires=datetime(2099, 1, 1, tzinfo=UTC))  # not expired
        result = assign(self.api_key_finding(key, admin_policies=()), CONFIG)

        assert (result.tier, result.if_reactivated) == (Tier.LOW, Tier.HIGH)

    def test_inactive_claude_platform_key_is_treated_the_same_way(self):
        key = self.api_key(kind="claude_api_key")
        result = assign(self.api_key_finding(key), CONFIG)

        assert (result.tier, result.if_reactivated) == (Tier.LOW, Tier.CRITICAL)

    def test_inactive_api_key_with_no_access_stays_info(self):
        result = assign(
            self.api_key_finding(self.api_key(), results=(), grant="none", admin_policies=()),
            CONFIG,
        )

        assert result.tier is Tier.INFO
        assert result.if_reactivated is None

    def test_the_access_key_reason_still_names_update_access_key(self):
        key = credential(active=False, age_days=390, unused_days=350)
        result = assign(self.inactive(credential=key, admin_policies=(ADMIN,)), CONFIG)

        assert result.reasons[0] == self.REENABLE

    def test_inactive_root_key_is_unchanged(self):
        root = finding(
            is_root=True,
            credential=credential(kind="root_access_key", active=False),
            admin_policies=(ADMIN,),
        )

        result = assign(root, CONFIG)

        assert result.tier is Tier.INFO
        assert result.reasons == ("The root access key is inactive.",)
        assert result.if_reactivated is None

    def test_unevaluated_permissions_stay_info_and_visible(self):
        result = assign(self.inactive(grant="unknown", results=()), CONFIG)

        assert result.tier is Tier.INFO

    def test_inactive_key_on_an_escalating_user_would_be_critical(self):
        result = assign(self.inactive(results=allowed(INVOKE, "aws-marketplace:Subscribe")), CONFIG)

        assert (result.tier, result.if_reactivated) == (Tier.LOW, Tier.CRITICAL)

    def test_the_would_be_tier_follows_the_real_rules(self):
        """An active copy must give exactly the tier and reasons the inactive key reports."""
        for overrides in (
            {"admin_policies": (ADMIN,)},
            {"mfa_active": False},
            {"results": allowed(INVOKE, *CONFIG.canary_actions)},
        ):
            active = assign(finding(**overrides), CONFIG)
            inactive = assign(self.inactive(**overrides), CONFIG)
            assert inactive.if_reactivated is active.tier
            assert inactive.reasons[2:] == active.reasons

    def test_threshold_changes_flow_through(self):
        """A 45-day-old key is High at 30 days and Medium at 90, and the inactive key follows."""
        key = credential(active=False, age_days=45, unused_days=1)
        assert assign(self.inactive(credential=key), Config(dormant_days=30)).tier is Tier.LOW
        assert assign(self.inactive(credential=key), Config(dormant_days=90)).tier is Tier.INFO

    def test_an_active_key_is_never_marked_as_reactivated(self):
        result = assign(finding(admin_policies=(ADMIN,)), CONFIG)

        assert result.tier is Tier.CRITICAL
        assert result.if_reactivated is None
