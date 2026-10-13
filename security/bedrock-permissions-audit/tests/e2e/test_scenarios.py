# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Requirements section 11, scenarios E3 to E12, E14 and E15, run through the real evaluator,
builder, scorer and sorter. Only the AWS responses are faked."""

import json
from dataclasses import replace
from pathlib import Path

from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.models import Tier
from bedrock_permissions_audit.output.rows import actions_allowed
from bedrock_permissions_audit.scoring.tiers import canary_allowed

from ..evaluator.fake_simulator import statements_from_document
from .dsl import ADMIN, HAIKU, allow, run, user, visible

INVOKE = ["bedrock:InvokeModel"]


def only(findings):
    assert len(findings) == 1, [f.principal_name for f in findings]
    return findings[0]


def test_e3_administrator_with_an_active_key_is_critical():
    finding = only(run(user("admin", allow=["*"], policies=[ADMIN])))
    assert finding.tier is Tier.CRITICAL
    assert "AdministratorAccess" in " ".join(finding.tier_reasons)


def test_e4_broad_grant_unused_200_days_with_mfa_is_high():
    finding = only(run(user("old", allow=INVOKE, unused=200, age=300, mfa=True)))
    assert finding.tier is Tier.HIGH
    assert finding.recommended_action.startswith("Delete access key")


def test_e5_same_permissions_but_fresh_and_in_use_is_medium():
    finding = only(run(user("fresh", allow=INVOKE, unused=1, age=10, mfa=True)))
    assert finding.tier is Tier.MEDIUM


def test_e6_grant_scoped_to_one_model_is_low():
    finding = only(run(user("scoped", allow=INVOKE, resources=[HAIKU], unused=1, age=10)))
    assert finding.tier is Tier.LOW
    assert finding.regions_allowed == ("eu-west-1",)


def test_e7_no_bedrock_permission_is_info_and_hidden_by_default():
    findings = run(user("s3only", allow=["s3:GetObject"]))
    assert only(findings).tier is Tier.INFO
    assert visible(findings) == []
    assert len(visible(findings, Config(show_all=True))) == 1


def test_e8_explicit_deny_in_an_attached_policy_beats_an_inline_allow():
    findings = run(
        user(
            "denied", allow=INVOKE, deny_actions=["bedrock:*"], extra=[allow(["bedrock-mantle:*"])]
        ),
    )
    # bedrock:* is denied; only the Mantle endpoint remains open, and it is still reported.
    assert only(findings).tier is not Tier.INFO


def test_e8_full_deny_is_info():
    finding = only(
        run(
            user(
                "denied",
                allow=["bedrock:*", "bedrock-mantle:*"],
                deny_actions=["bedrock:*", "bedrock-mantle:*"],
            )
        )
    )
    assert finding.tier is Tier.INFO


def test_e9_bedrock_api_key_user_without_an_access_key_is_high():
    finding = only(
        run(
            user(
                "BedrockAPIKey-ab12",
                allow=["bedrock:CallWithBearerToken"],
                phantom=True,
                api_key=True,
                age=20,
                mfa=False,
            )
        )
    )
    assert finding.tier is Tier.HIGH
    assert "API key" in finding.recommended_action
    assert finding.credential.kind == "bedrock_api_key"


def test_e10_orphaned_api_key_user_is_medium():
    finding = only(
        run(user("BedrockAPIKey-ab12", allow=INVOKE, phantom=True, active=False, api_key=True))
    )
    assert finding.orphaned is True
    assert finding.tier is Tier.MEDIUM
    assert finding.recommended_action.startswith("Delete the IAM user BedrockAPIKey-ab12")


def test_e10_phantom_user_with_no_credential_at_all_is_also_orphaned():
    finding = only(run(user("BedrockAPIKey-zz", allow=INVOKE, phantom=True, no_credential=True)))
    assert finding.orphaned is True
    assert finding.credential is None


def test_e11_root_access_key_is_critical_and_the_first_row():
    findings = run(
        user("admin", allow=["*"], policies=[ADMIN], age=5000),
        user("<root_account>", root=True, age=1),
        user("old", allow=INVOKE, unused=999),
    )
    assert findings[0].is_root is True
    assert findings[0].tier is Tier.CRITICAL


def test_e12_marketplace_subscribe_plus_invoke_is_critical():
    finding = only(run(user("sub", allow=INVOKE + ["aws-marketplace:Subscribe"])))
    assert finding.tier is Tier.CRITICAL
    assert "aws-marketplace:Subscribe" in " ".join(finding.tier_reasons)


def test_self_scoped_api_key_creation_is_critical_and_found():
    own_arn = "arn:aws:iam::123456789012:user/minter"
    finding = only(
        run(
            user(
                "minter",
                allow=INVOKE,
                extra=[allow(["iam:CreateServiceSpecificCredential"], [own_arn])],
            )
        )
    )
    assert finding.tier is Tier.CRITICAL


def test_e14_permission_boundary_that_denies_overrides_an_allow():
    from tests.evaluator.fake_simulator import allow as boundary_allow

    finding = only(run(user("bounded", allow=["*"], boundary=[boundary_allow(["s3:*"])])))
    assert finding.tier is Tier.INFO


def test_e15_threshold_of_30_days():
    config = Config(dormant_days=30)
    fresh = user("fresh", allow=INVOKE, age=10, unused=1)
    stale = user("stale", allow=INVOKE, age=100, unused=45)

    by_name = {f.principal_name: f for f in run(fresh, stale, config=config)}

    assert by_name["fresh"].tier is Tier.MEDIUM  # unchanged
    assert by_name["stale"].tier is Tier.HIGH


def test_dormant_key_outranks_an_active_key_with_identical_permissions():
    findings = run(
        user("active-no-mfa", allow=INVOKE, mfa=False, age=500, unused=1),
        user("dormant", allow=INVOKE, mfa=True, age=100, unused=300),
    )
    assert [f.principal_name for f in findings] == ["dormant", "active-no-mfa"]


def test_nobody_without_bedrock_permissions_ranks_above_info():
    """Precision: ranking only ever contains principals that can reach Amazon Bedrock."""
    findings = run(
        user("a", allow=["s3:*"], unused=999, mfa=False, age=999),
        user("b", allow=["ec2:*"], unused=None, mfa=False, age=999),
        user("c", allow=["iam:ListUsers"], unused=999),
        user("d", allow=INVOKE, unused=999),
    )
    ranked = [f.principal_name for f in findings if f.tier is not Tier.INFO]
    assert ranked == ["d"]


def test_every_bedrock_capable_principal_is_ranked():
    """Recall: nobody who can invoke Amazon Bedrock is missed or left at Info."""
    names = ["u1", "u2", "u3", "u4", "u5"]
    findings = run(
        user("u1", allow=INVOKE),
        user("u2", allow=["bedrock:*"]),
        user("u3", allow=["bedrock:Converse*"]),
        user("u4", allow=["bedrock:CallWithBearerToken"]),
        user("u5", allow=INVOKE, resources=[HAIKU]),
    )
    assert sorted(f.principal_name for f in findings if f.tier is not Tier.INFO) == names


def test_two_active_keys_on_one_user_produce_two_rows():
    spec = user("twice", allow=INVOKE)
    second = user("twice", allow=INVOKE, unused=300).principal.access_keys[0]
    spec.principal = replace(spec.principal, access_keys=spec.principal.access_keys + (second,))

    findings = run(spec)

    assert len(findings) == 2
    assert sorted(f.tier for f in findings) == [Tier.HIGH, Tier.MEDIUM]


def test_unevaluable_principal_is_reported_not_dropped():
    from bedrock_permissions_audit.audit import build_findings
    from bedrock_permissions_audit.evaluator import SimulatorEvaluator, safe_evaluate
    from tests.evaluator.fake_simulator import FakeIam  # noqa: F401  - documents the dependency

    from .dsl import ACCOUNT

    spec = user("throttled", allow=INVOKE)
    evaluation = safe_evaluate(
        SimulatorEvaluator(FakeIam([], raise_error="Throttling"), Config()), spec.principal
    )
    (finding,) = build_findings(ACCOUNT, spec.principal, evaluation, Config())

    assert finding.grant == "unknown"
    assert finding.tier is Tier.INFO
    assert "Throttling" in finding.warnings[0]
    assert visible([finding]) == [finding]


def two_inactive_keys(name, **kwargs):
    """A user at the two-key limit with both keys deactivated, as in the reported account."""
    spec = user(name, active=False, age=390, unused=350, mfa=False, **kwargs)
    second = user(name, active=False, age=163, unused=161, mfa=False).principal.access_keys[0]
    spec.principal = replace(spec.principal, access_keys=(*spec.principal.access_keys, second))
    return spec


def test_e17_admin_user_with_only_inactive_keys_is_reported_without_all():
    """Previously this printed "No findings to report"."""
    findings = run(two_inactive_keys("testwing", allow=["*"], policies=[ADMIN]))

    shown = visible(findings)  # default config: no --all

    assert [f.tier for f in shown] == [Tier.LOW, Tier.LOW]
    assert all(f.if_reactivated_tier is Tier.CRITICAL for f in shown)
    assert all(f.recommended_action.startswith("Delete inactive access key") for f in shown)
    assert all("admin-class permissions" in f.recommended_action for f in shown)
    assert all("If re-enabled it would rate Critical:" in f.tier_reasons for f in shown)
    assert all(
        f.tier_reasons[0].startswith("The key is inactive but its secret works again")
        for f in shown
    )


def test_e17_inactive_keys_on_a_user_with_no_amazon_bedrock_access_stay_hidden():
    findings = run(two_inactive_keys("s3user", allow=["s3:GetObject"]))

    assert [f.tier for f in findings] == [Tier.INFO, Tier.INFO]
    assert visible(findings) == []
    assert all(
        f.recommended_action == "No action needed for Amazon Bedrock exposure." for f in findings
    )


def test_e17_an_inactive_key_beside_an_active_one_is_each_rated_on_its_own():
    spec = user("mixed", allow=INVOKE, policies=[ADMIN], age=10, unused=1, mfa=True)
    inactive = user("mixed", allow=INVOKE, active=False, age=390, unused=350, mfa=False)
    spec.principal = replace(
        spec.principal, access_keys=(*spec.principal.access_keys, *inactive.principal.access_keys)
    )

    findings = run(spec)

    assert sorted(f.tier for f in findings) == [Tier.CRITICAL, Tier.LOW]
    low = next(f for f in findings if f.tier is Tier.LOW)
    assert low.if_reactivated_tier is Tier.CRITICAL


def test_e17_inactive_root_key_is_unchanged():
    findings = run(user("<root_account>", root=True, active=False, age=3000, unused=None))

    assert [f.tier for f in findings] == [Tier.INFO]
    assert findings[0].recommended_action.startswith("Delete the inactive root access key")
    assert visible(findings) == []


def test_e17_the_acceptance_ordering_in_a_mixed_report():
    findings = run(
        two_inactive_keys("would-be-high", allow=INVOKE),
        two_inactive_keys("would-be-critical", allow=["*"], policies=[ADMIN]),
        user("scoped", allow=INVOKE, resources=[HAIKU], age=5, unused=0, mfa=True),
    )

    low = [(f.principal_name, f.if_reactivated_tier) for f in findings if f.tier is Tier.LOW]

    assert [name for name, _ in low] == [
        "would-be-critical",
        "would-be-critical",
        "would-be-high",
        "would-be-high",
        "scoped",
    ]


# ---------------------------------------------------------------------------------------------
# E18: a model outside the bundled sample
# ---------------------------------------------------------------------------------------------

TITAN = "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1"


def test_e18_a_model_outside_the_bundled_sample_is_ranked_not_hidden():
    findings = run(user("titan-only", allow=INVOKE, resources=[TITAN], age=5, unused=0, mfa=True))

    (finding,) = visible(findings)  # default config: no --all

    assert finding.grant == "scoped"
    assert finding.regions_allowed == ("us-east-1",)
    assert finding.tier is Tier.LOW


def test_e18_a_named_model_the_simulator_denies_is_shown_for_review():
    spec = user("hidden-allow", allow=INVOKE, resources=[TITAN], age=5, unused=0, mfa=True)
    spec.boundary = [allow(["s3:*"])]  # a boundary the Allow cannot see through

    (finding,) = visible(run(spec))

    assert finding.grant == "unknown"
    assert finding.tier is Tier.INFO
    assert any("Review it manually" in w for w in finding.warnings)


# ---------------------------------------------------------------------------------------------
# E19: AmazonBedrockLimitedAccess is not bedrock:*
# ---------------------------------------------------------------------------------------------

LIMITED_ACCESS = json.loads(
    (
        Path(__file__).resolve().parents[1] / "fixtures" / "AmazonBedrockLimitedAccess.v9.json"
    ).read_text()
)


def limited_access_statements():
    """The real managed policy. The fake does not evaluate conditions, so leave out the one
    statement that has one (Marketplace): the real simulator denies it for lack of context."""
    unconditioned = {
        "Version": LIMITED_ACCESS["Version"],
        "Statement": [s for s in LIMITED_ACCESS["Statement"] if "Condition" not in s],
    }
    return statements_from_document(unconditioned, policy="AmazonBedrockLimitedAccess")


def limited_access_user(name="BedrockAPIKey-limited", **kwargs):
    values = {"extra": limited_access_statements(), "phantom": True, "api_key": True, "age": 3}
    values.update(kwargs)
    return user(name, **values)


def test_e19_the_real_managed_policy_grants_some_but_not_all_canary_actions():
    """What the real simulator reported for this exact document (v9, checked live)."""
    config = Config()
    finding = only(run(limited_access_user(), config=config))
    allowed_now = {r.action for r in finding.results if r.decision == "allowed"}

    assert {
        "bedrock:DeleteCustomModel",
        "bedrock:DeleteGuardrail",
        "bedrock:CreateProvisionedModelThroughput",
    } <= allowed_now
    assert allowed_now.isdisjoint(
        {
            "bedrock:PutModelInvocationLoggingConfiguration",
            "bedrock:DeleteAgent",
            "bedrock:DeleteKnowledgeBase",
        }
    )


def test_e19_a_user_holding_limited_access_is_not_called_bedrock_star():
    finding = only(run(limited_access_user()))

    assert not canary_allowed(finding, Config())
    assert not any("bedrock:*" in reason for reason in finding.tier_reasons)
    assert "bedrock:* (effective)" not in actions_allowed(finding, Config())
    assert not any(
        a.startswith("Replace the broad permissions") for a in [finding.recommended_action]
    )


def test_e19_it_is_an_api_key_user_so_it_is_high_not_critical():
    finding = only(run(limited_access_user()))

    assert finding.tier is Tier.HIGH
    assert finding.tier_reasons == (
        "An Amazon Bedrock API key is a bearer token that works from anywhere.",
    )


def test_e19_with_the_old_one_action_canary_the_same_document_was_called_bedrock_star():
    """The reported bug, reproduced by configuring the old single-action canary."""
    old = Config(canary_actions=("bedrock:DeleteCustomModel",))

    finding = only(run(limited_access_user(), config=old))

    assert canary_allowed(finding, old)
    assert finding.tier is Tier.CRITICAL


def test_e19_a_user_who_really_holds_bedrock_star_is_still_critical():
    finding = only(run(user("real-bedrock-star", allow=["bedrock:*"], mfa=True, age=5, unused=0)))

    assert canary_allowed(finding, Config())
    assert finding.tier is Tier.CRITICAL
    assert any("bedrock:*" in reason for reason in finding.tier_reasons)
    assert "bedrock:* (effective)" in actions_allowed(finding, Config())


def test_e19_an_access_key_user_with_limited_access_is_ranked_on_its_own_facts():
    spec = user(
        "limited-access-key-user",
        extra=limited_access_statements(),
        age=5,
        unused=0,
        mfa=True,
    )

    finding = only(run(spec))

    assert not canary_allowed(finding, Config())
    assert finding.tier is Tier.MEDIUM  # broad, recent, in use, MFA on


# ---------------------------------------------------------------------------------------------
# E17 (extended): inactive Amazon Bedrock API keys
# ---------------------------------------------------------------------------------------------


def test_e17_an_inactive_amazon_bedrock_api_key_is_reported_without_all():
    spec = user(
        "apikey-admin",
        allow=["*"],
        policies=[ADMIN],
        api_key=True,
        active=False,
        age=200,
        mfa=False,
    )

    (finding,) = visible(run(spec))

    assert finding.tier is Tier.LOW
    assert finding.if_reactivated_tier is Tier.CRITICAL
    assert "iam:UpdateServiceSpecificCredential" in finding.tier_reasons[0]
    assert finding.recommended_action.startswith("Delete inactive API key")
    assert "including admin-class permissions" in finding.recommended_action
    assert "It is unused" not in finding.recommended_action  # IAM does not report API key use


def test_e17_an_expired_amazon_bedrock_api_key_stays_hidden():
    spec = user(
        "apikey-expired", allow=["*"], policies=[ADMIN], api_key=True, active=False, age=200
    )
    spec.principal = replace(
        spec.principal,
        api_keys=tuple(replace(k, expired=True) for k in spec.principal.api_keys),
    )

    findings = run(spec)

    assert [f.tier for f in findings] == [Tier.INFO]
    assert visible(findings) == []
    assert findings[0].recommended_action.startswith("Delete the expired API key")
