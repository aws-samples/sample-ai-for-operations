# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from dataclasses import replace

import pytest

from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.models import Tier
from bedrock_permissions_audit.scoring import score
from bedrock_permissions_audit.scoring.ordering import is_visible, sort_findings

from .factories import ADMIN, INVOKE, KEY_ID, allowed, credential, finding

CONFIG = Config()


def scored(**overrides):
    return score(finding(**overrides), CONFIG)


class TestOrdering:
    def test_tiers_sort_critical_first(self):
        medium = scored()
        critical = scored(admin_policies=(ADMIN,), principal_name="zed")
        low = scored(grant="scoped", principal_name="amy")

        assert sort_findings([low, medium, critical], CONFIG) == [critical, medium, low]

    def test_root_is_first_in_the_critical_tier(self):
        admin = scored(admin_policies=(ADMIN,), credential=credential(age_days=3000))
        root = scored(
            is_root=True,
            principal_name="<root_account>",
            credential=credential(kind="root_access_key", age_days=1),
        )

        assert sort_findings([admin, root], CONFIG)[0] is root

    def test_dormant_outranks_an_active_key_with_identical_permissions(self):
        """Requirement 10: both are High, but the dormant one is listed first."""
        active_no_mfa = scored(
            mfa_active=False, credential=credential(age_days=500), principal_name="aaa"
        )
        dormant = scored(credential=credential(unused_days=200, age_days=100), principal_name="zzz")
        assert active_no_mfa.tier is dormant.tier is Tier.HIGH

        assert sort_findings([active_no_mfa, dormant], CONFIG)[0] is dormant

    def test_older_keys_come_first_within_equal_dormancy(self):
        older = scored(credential=credential(unused_days=200, age_days=900), principal_name="zzz")
        newer = scored(credential=credential(unused_days=200, age_days=100), principal_name="aaa")

        assert sort_findings([newer, older], CONFIG) == [older, newer]

    def test_wider_region_coverage_breaks_ties(self):
        wide = scored(regions_allowed=("a-1-1", "b-1-1", "c-1-1"), principal_name="zzz")
        narrow = scored(regions_allowed=("a-1-1",), principal_name="aaa")

        assert sort_findings([narrow, wide], CONFIG)[0] is wide

    def test_low_orders_inactive_would_be_critical_then_would_be_high_then_ordinary(self):
        """The tie-breakers all favour the ordinary finding (older, alphabetically first, more
        Regions), so the reactivation rank has to be what puts it last."""
        # A Low finding needs a young, in-use key. It still wins every tie-break below the rank:
        # alphabetically first, and the most Regions.
        ordinary = scored(
            grant="scoped",
            principal_name="aaa",
            credential=credential(age_days=80, unused_days=0),
            regions_allowed=("a-1-1", "b-1-1", "c-1-1"),
        )
        would_be_high = scored(
            principal_name="bbb",
            mfa_active=False,
            credential=credential(active=False, age_days=100, unused_days=161),
        )
        would_be_critical = scored(
            principal_name="ccc",
            admin_policies=(ADMIN,),
            credential=credential(active=False, age_days=100, unused_days=161),
        )
        assert (ordinary.tier, would_be_high.tier, would_be_critical.tier) == (Tier.LOW,) * 3
        assert would_be_critical.if_reactivated_tier is Tier.CRITICAL
        assert would_be_high.if_reactivated_tier is Tier.HIGH
        assert ordinary.if_reactivated_tier is None

        ordered = sort_findings([ordinary, would_be_high, would_be_critical], CONFIG)

        assert ordered == [would_be_critical, would_be_high, ordinary]

    def test_the_reactivation_rank_never_moves_a_finding_out_of_its_tier(self):
        critical = scored(admin_policies=(ADMIN,), principal_name="zzz")
        inactive = scored(
            admin_policies=(ADMIN,),
            principal_name="aaa",
            credential=credential(active=False, unused_days=300, age_days=400),
        )
        medium = scored(principal_name="mmm")

        assert sort_findings([medium, inactive, critical], CONFIG) == [critical, medium, inactive]

    def test_inactive_findings_that_stay_info_are_unaffected_by_the_new_rank(self):
        plain = scored(credential=credential(active=False), principal_name="bbb")
        also_plain = scored(credential=credential(active=False), principal_name="aaa")

        assert plain.tier is also_plain.tier is Tier.INFO
        assert sort_findings([plain, also_plain], CONFIG) == [also_plain, plain]

    def test_order_is_deterministic_for_full_ties(self):
        first = scored(principal_name="alice")
        second = scored(principal_name="bob")

        assert sort_findings([second, first], CONFIG) == [first, second]


class TestVisibility:
    def info(self, **overrides):
        return scored(results=allowed("s3:GetObject"), grant="none", **overrides)

    def test_info_rows_are_hidden_by_default(self):
        assert is_visible(self.info(), CONFIG) is False

    def test_info_rows_show_with_all(self):
        assert is_visible(self.info(), Config(show_all=True)) is True

    def test_ranked_rows_are_always_visible(self):
        assert is_visible(scored(), CONFIG) is True

    def test_an_inactive_key_that_would_be_critical_is_visible_without_all(self):
        """The reported bug: this used to print "No findings to report"."""
        inactive = scored(
            admin_policies=(ADMIN,),
            mfa_active=False,
            credential=credential(active=False, age_days=390, unused_days=350),
        )
        assert inactive.tier is Tier.LOW
        assert is_visible(inactive, CONFIG) is True

    def test_an_inactive_key_that_stays_info_is_still_hidden_without_all(self):
        inactive = scored(credential=credential(active=False))
        assert inactive.tier is Tier.INFO
        assert is_visible(inactive, CONFIG) is False
        assert is_visible(inactive, Config(show_all=True)) is True

    def test_unknown_rows_are_never_hidden(self):
        unknown = scored(grant="unknown", results=())
        assert unknown.tier is Tier.INFO
        assert is_visible(unknown, CONFIG) is True


class TestRecommendations:
    def action(self, **overrides) -> str:
        return scored(**overrides).recommended_action

    def test_root_key(self):
        text = self.action(is_root=True, credential=credential(kind="root_access_key"))
        assert text.startswith("Delete the root access key")

    def test_orphaned_phantom_user_names_the_user(self):
        text = self.action(
            orphaned=True, credential=None, is_phantom=True, principal_name="BedrockAPIKey-ab12"
        )
        assert "Delete the IAM user BedrockAPIKey-ab12" in text

    def test_api_key_advice_names_both_bearer_token_actions(self):
        text = self.action(
            credential=credential(
                kind="bedrock_api_key",
                key_id="ABCD1234ABCD1234ABCD1",
                unused_days=None,
                last_used=None,
                last_used_known=False,
            ),
            results=allowed("bedrock:CallWithBearerToken"),
        )
        assert "bedrock:CallWithBearerToken" in text
        assert "bedrock-mantle:CallWithBearerToken" in text
        assert "...BCD1" in text  # masked
        assert "ABCD1234ABCD1234ABCD1" not in text  # never the full ID

    def test_dormant_key_says_delete_and_how_long(self):
        text = self.action(credential=credential(unused_days=400, age_days=500))
        assert text.startswith("Delete access key ...MPLE (unused for 400 days)")

    def test_never_used_key_says_never_used(self):
        text = self.action(credential=credential(unused_days=None, last_used=None))
        assert "never used" in text

    def test_escalation_action_is_named(self):
        text = self.action(results=allowed(INVOKE, "aws-marketplace:Subscribe"))
        assert text.startswith("Remove aws-marketplace:Subscribe from alice")

    def test_admin_user_is_told_to_narrow_permissions(self):
        assert "limited to the Amazon Bedrock actions" in self.action(admin_policies=(ADMIN,))

    def test_no_mfa_active_key_is_told_to_use_a_role(self):
        text = self.action(mfa_active=False)
        assert "IAM role" in text
        assert "enable MFA" in text

    def test_low_tier_needs_no_urgent_action(self):
        assert self.action(grant="scoped").startswith("No urgent action")

    def test_info_cannot_invoke(self):
        assert self.action(results=allowed("s3:GetObject"), grant="none").startswith(
            "No action needed"
        )

    def test_unknown_asks_for_manual_review(self):
        assert "manually" in self.action(grant="unknown", results=())

    def test_inactive_admin_key_is_told_to_be_deleted_and_admin_class_is_named(self):
        text = self.action(
            credential=credential(active=False, age_days=390, unused_days=350),
            mfa_active=False,
            admin_policies=(ADMIN,),
        )
        assert text == (
            "Delete inactive access key ...MPLE on alice. It is unused, and re-enabling it "
            "would restore Amazon Bedrock access, including admin-class permissions."
        )

    def test_inactive_high_key_without_admin_policy_does_not_claim_admin_class(self):
        text = self.action(
            credential=credential(active=False, age_days=163, unused_days=161), mfa_active=False
        )
        assert text == (
            "Delete inactive access key ...MPLE on alice. It is unused, and re-enabling it "
            "would restore Amazon Bedrock access."
        )
        assert "admin-class" not in text

    def test_inactive_key_with_no_amazon_bedrock_access_needs_no_action(self):
        text = self.action(
            credential=credential(active=False), results=allowed("s3:GetObject"), grant="none"
        )
        assert text == "No action needed for Amazon Bedrock exposure."
        assert "Delete the credential if unused" not in text

    def test_inactive_key_that_would_rate_below_high_is_still_told_to_be_deleted(self):
        """Medium if it were active, so it is not raised, but it still has no reason to exist."""
        text = self.action(credential=credential(active=False))
        assert text == "Delete inactive access key ...MPLE; it has no reason to exist."

    def test_expired_api_key_is_not_called_an_access_key(self):
        expired = credential(
            kind="bedrock_api_key",
            key_id="ABCD1234ABCD1234ABCD1",
            active=False,
            unused_days=None,
            last_used=None,
            last_used_known=False,
        )
        text = self.action(
            credential=expired, results=allowed("bedrock:CallWithBearerToken"), is_phantom=True
        )
        assert "access key" not in text
        assert "API key ...BCD1" in text

    def test_inactive_root_key_advice_is_unchanged(self):
        text = self.action(
            is_root=True, credential=credential(kind="root_access_key", active=False)
        )
        assert text == "Delete the inactive root access key; root should have no access keys."

    def test_every_inactive_branch_masks_the_key_id(self):
        for overrides in (
            {
                "credential": credential(active=False),
                "admin_policies": (ADMIN,),
                "mfa_active": False,
            },
            {"credential": credential(active=False)},
            {"credential": credential(active=False), "grant": "none", "results": ()},
        ):
            text = self.action(**overrides)
            assert KEY_ID not in text
            assert text

    @pytest.mark.parametrize(
        "overrides",
        [
            {},
            {"mfa_active": False},
            {"admin_policies": (ADMIN,)},
            {"grant": "scoped"},
            {"credential": credential(unused_days=400)},
            {"credential": credential(unused_days=None, last_used=None)},
        ],
    )
    def test_no_recommendation_ever_contains_a_full_key_id(self, overrides):
        assert KEY_ID not in self.action(**overrides)
        assert self.action(**overrides)  # and it is never empty

    def test_score_fills_tier_reasons_and_action(self):
        result = score(finding(admin_policies=(ADMIN,)), CONFIG)
        assert result.tier is Tier.CRITICAL
        assert result.tier_reasons
        assert result.recommended_action
        assert replace(result, tier=Tier.INFO).tier is Tier.INFO  # frozen: replace, not assign
