# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import pytest

from bedrock_permissions_audit.config import Config, effective_regions
from bedrock_permissions_audit.evaluator import (
    ROOT_STATEMENT,
    SimulatorEvaluator,
    safe_evaluate,
)
from bedrock_permissions_audit.models import Principal

from .fake_simulator import FakeIam, allow, deny

ACCOUNT = "123456789012"
ARN = f"arn:aws:iam::{ACCOUNT}:user/alice"
ALL_BEDROCK = ("bedrock:*", "bedrock-mantle:*")
HAIKU_EU = "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"


def principal(**overrides):
    return Principal(**{"account_id": ACCOUNT, "name": "alice", "arn": ARN, **overrides})


def evaluate(iam, config=None, **principal_overrides):
    return SimulatorEvaluator(iam, config or Config()).evaluate(principal(**principal_overrides))


def decisions(evaluation, action):
    return {r.resource: r.decision for r in evaluation.results if r.action == action}


def test_resource_star_grant_is_broad_and_costs_one_call():
    iam = FakeIam([allow(["bedrock:InvokeModel"], policy="InvokePolicy")])

    result = evaluate(iam)

    assert result.grant == "broad"
    assert decisions(result, "bedrock:InvokeModel") == {"*": "allowed"}
    assert result.regions_allowed == effective_regions(Config())
    assert (
        "InvokePolicy (IAM Policy)"
        in next(r for r in result.results if r.action == "bedrock:InvokeModel").matched_statements
    )
    assert not any("ResourceArns" in c and c["ResourceArns"] != [ARN] for c in iam.calls)


def test_wildcard_over_all_foundation_models_is_effectively_broad():
    iam = FakeIam([allow(["bedrock:InvokeModel*"], ["arn:aws:bedrock:*::foundation-model/*"])])

    result = evaluate(iam)

    assert result.grant == "broad"
    assert len(result.regions_allowed) == len(effective_regions(Config()))


def test_one_model_in_one_region_is_scoped():
    iam = FakeIam(
        [
            allow(
                ["bedrock:InvokeModel"],
                [
                    "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
                ],
            )
        ]
    )

    result = evaluate(iam)

    assert result.grant == "scoped"
    assert result.regions_allowed == ("eu-west-1",)


def test_one_model_in_every_region_is_scoped_not_broad():
    iam = FakeIam(
        [
            allow(
                ["bedrock:InvokeModel"],
                ["arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"],
            )
        ]
    )

    result = evaluate(iam)

    assert result.grant == "scoped"
    assert len(result.regions_allowed) == len(effective_regions(Config()))


def test_grant_only_on_inference_profiles_is_detected():
    iam = FakeIam(
        [allow(["bedrock:InvokeModel"], [f"arn:aws:bedrock:*:{ACCOUNT}:inference-profile/*"])]
    )

    assert evaluate(iam).grant == "scoped"


def test_unrelated_permissions_are_none():
    result = evaluate(FakeIam([allow(["s3:GetObject"])]))

    assert result.grant == "none"
    assert result.regions_allowed == ()
    assert set(decisions(result, "bedrock:InvokeModel").values()) == {"implicitDeny"}


def test_e8_explicit_deny_beats_allow():
    iam = FakeIam([allow(ALL_BEDROCK), deny(ALL_BEDROCK, policy="DenyBedrock")])

    result = evaluate(iam)

    assert result.grant == "none"
    assert "explicitDeny" in set(decisions(result, "bedrock:InvokeModel").values())


def test_denying_only_bedrock_star_leaves_the_mantle_endpoint_open():
    """bedrock:* does not cover bedrock-mantle:*, a real gap in deny policies written before
    the Mantle endpoint existed. The audit must still report the principal."""
    iam = FakeIam([allow(ALL_BEDROCK), deny(["bedrock:*"], policy="DenyBedrock")])

    result = evaluate(iam)

    assert result.grant == "broad"
    assert decisions(result, "bedrock-mantle:CallWithBearerToken") == {"*": "allowed"}
    assert set(decisions(result, "bedrock:InvokeModel").values()) == {"explicitDeny"}


def test_e14_permission_boundary_that_denies_overrides_an_allow():
    iam = FakeIam([allow(["*"])], boundary=[allow(["s3:*"])])

    assert evaluate(iam).grant == "none"


def test_boundary_that_permits_keeps_the_grant():
    iam = FakeIam([allow(["bedrock:*"])], boundary=[allow(["bedrock:*"])])

    assert evaluate(iam).grant == "broad"


def test_bearer_token_actions_count_as_invoke():
    result = evaluate(FakeIam([allow(["bedrock:CallWithBearerToken"])]))

    assert result.grant == "broad"


def test_custom_invoke_action_set_is_respected():
    config = Config(invoke_actions=("bedrock:InvokeModel",))
    iam = FakeIam([allow(["bedrock:CallWithBearerToken"])])

    assert evaluate(iam, config).grant == "none"


def test_self_scoped_api_key_creation_is_found_by_the_own_arn_check():
    iam = FakeIam([allow(["iam:CreateServiceSpecificCredential"], [ARN])])

    result = evaluate(iam)

    assert decisions(result, "iam:CreateServiceSpecificCredential")["*"] == "implicitDeny"
    assert decisions(result, "iam:CreateServiceSpecificCredential")[ARN] == "allowed"


def test_own_arn_check_is_skipped_when_star_already_allows_it():
    iam = FakeIam([allow(["iam:CreateServiceSpecificCredential"])])

    evaluate(iam)

    assert not any(c.get("ResourceArns") == [ARN] for c in iam.calls)


def test_resource_list_is_chunked():
    iam = FakeIam([allow(["s3:*"])])

    evaluate(iam)

    chunks = [c["ResourceArns"] for c in iam.calls if len(c.get("ResourceArns", [])) > 1]
    assert len(chunks) >= 2
    assert all(len(chunk) <= 25 for chunk in chunks)
    # The default invoke actions fall into two authorization groups, and every sampled ARN is
    # queried once per group and never twice within one.
    counts = {}
    for chunk in chunks:
        for arn in chunk:
            counts[arn] = counts.get(arn, 0) + 1
    assert set(counts.values()) == {2}


def test_scoped_path_does_not_waste_calls_on_rejected_batches():
    """Regression: the real simulator rejects incompatible actions in one call. Learning the
    groups once means the scoped path costs a handful of calls, not one per action."""
    config = Config()
    evaluator = SimulatorEvaluator(FakeIam([allow(["s3:*"])]), config)

    evaluator.evaluate(principal())
    first = len(evaluator._iam.calls)
    rejected_first = [
        c for c in evaluator._iam.calls if "ResourceArns" in c and len(_groups_in(c)) > 1
    ]
    evaluator._iam.calls.clear()

    evaluator.evaluate(principal(name="bob", arn=f"arn:aws:iam::{ACCOUNT}:user/bob"))
    second = len(evaluator._iam.calls)
    rejected_second = [
        c for c in evaluator._iam.calls if "ResourceArns" in c and len(_groups_in(c)) > 1
    ]

    # The first principal pays for learning which actions can share a call (a few rejected
    # probes); every later principal pays nothing for it.
    assert 0 < len(rejected_first) <= 6
    assert rejected_second == []
    assert second < first
    assert second <= 8, f"{second} calls for one principal"


def test_incompatible_actions_are_split_into_groups_the_simulator_accepts():
    iam = FakeIam([allow(["bedrock:*"], [HAIKU_EU])])

    result = evaluate(iam)

    assert result.grant == "scoped"
    assert result.warnings == ()
    assert {r.action for r in result.results if r.decision == "allowed"} == {
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:Converse",
        "bedrock:ConverseStream",
        "bedrock:CallWithBearerToken",
        "bedrock-mantle:CallWithBearerToken",
    } - {"bedrock-mantle:CallWithBearerToken"}  # bedrock:* does not cover bedrock-mantle


def _groups_in(call):
    from .fake_simulator import _authorization_groups

    return _authorization_groups(call["ActionNames"])


def test_a_rejected_action_name_is_reported_and_the_rest_still_evaluated():
    iam = FakeIam([allow(["bedrock:InvokeModel"])], reject_actions={"bedrock:Converse"})

    result = evaluate(iam)

    assert result.grant == "broad"
    assert any("bedrock:Converse" in w and "rejected" in w for w in result.warnings)
    assert "bedrock:Converse" not in {r.action for r in result.results}
    assert "bedrock:InvokeModel" in {r.action for r in result.results}


def test_root_is_allowed_everywhere_without_calling_the_simulator():
    iam = FakeIam([])

    result = evaluate(iam, is_root=True, name="<root_account>", arn=f"arn:aws:iam::{ACCOUNT}:root")

    assert result.grant == "broad"
    assert iam.calls == []
    assert {r.decision for r in result.results} == {"allowed"}
    assert result.results[0].matched_statements == (ROOT_STATEMENT,)
    assert {r.action for r in result.results} == set(Config().all_actions)


class TestSafeEvaluate:
    def test_throttling_becomes_unknown_with_a_warning(self):
        evaluator = SimulatorEvaluator(FakeIam([], raise_error="Throttling"), Config())

        result = safe_evaluate(evaluator, principal())

        assert result.grant == "unknown"
        assert "Throttling" in result.warnings[0]
        assert "alice" in result.warnings[0]

    @pytest.mark.parametrize("code", ["AccessDenied", "ExpiredToken", "AccessDeniedException"])
    def test_permission_and_credential_errors_are_not_hidden(self, code):
        from botocore.exceptions import ClientError

        evaluator = SimulatorEvaluator(FakeIam([], raise_error=code), Config())

        with pytest.raises(ClientError):
            safe_evaluate(evaluator, principal())

    def test_success_passes_through(self):
        evaluator = SimulatorEvaluator(FakeIam([allow(["bedrock:*"])]), Config())

        assert safe_evaluate(evaluator, principal()).grant == "broad"


class TestModelsOutsideTheBundledSample:
    """Bug: when no invoke action was allowed on '*' and every bundled sample model was denied, a
    policy allowing some other model was reported as grant 'none' and hidden as Info."""

    TITAN = "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1"

    def test_the_titan_model_is_really_outside_the_bundled_sample(self):
        """Guards the premise of the tests below: if the sample ever gains this model they prove
        nothing."""
        from bedrock_permissions_audit.config import effective_models

        assert "amazon.titan-text-lite-v1" not in effective_models(Config())

    def test_a_model_outside_the_sample_is_found_as_scoped(self):
        iam = FakeIam([allow(["bedrock:InvokeModel"], [self.TITAN])])

        result = evaluate(iam)

        assert result.grant == "scoped"
        assert result.regions_allowed == ("us-east-1",)
        assert decisions(result, "bedrock:InvokeModel")[self.TITAN] == "allowed"
        assert result.warnings == ()

    def test_without_reading_the_policies_it_would_have_been_missed(self):
        """The same policy, with the reader switched off, reproduces the reported bug."""

        class NothingNamed:
            def resources_for(self, principal):
                return ()

        iam = FakeIam([allow(["bedrock:InvokeModel"], [self.TITAN])])

        result = SimulatorEvaluator(iam, Config(), policy_reader=NothingNamed()).evaluate(
            principal()
        )

        assert result.grant == "none"

    def test_a_model_in_a_region_that_is_not_configured_is_still_tested(self):
        arn = "arn:aws:bedrock:ap-southeast-4::foundation-model/amazon.titan-text-lite-v1"
        iam = FakeIam([allow(["bedrock:InvokeModel"], [arn])])

        result = evaluate(iam, Config(bedrock_regions=("us-east-1",)))

        assert (result.grant, result.regions_allowed) == ("scoped", ("ap-southeast-4",))

    def test_a_wildcard_region_is_expanded_and_reported_per_region(self):
        arn = "arn:aws:bedrock:*::foundation-model/amazon.titan-text-lite-v1"
        iam = FakeIam([allow(["bedrock:InvokeModel"], [arn])])
        config = Config(bedrock_regions=("us-east-1", "eu-west-1", "ap-south-1"))

        result = evaluate(iam, config)

        assert result.grant == "scoped"
        assert result.regions_allowed == ("ap-south-1", "eu-west-1", "us-east-1")

    def test_a_pattern_for_a_family_of_unlisted_models_is_found(self):
        arn = "arn:aws:bedrock:us-east-1::foundation-model/ai21.*"
        iam = FakeIam([allow(["bedrock:InvokeModel"], [arn])])

        result = evaluate(iam)

        assert result.grant == "scoped"
        assert result.regions_allowed == ("us-east-1",)

    def test_a_managed_policy_naming_the_model_is_read(self):
        policy_arn = f"arn:aws:iam::{ACCOUNT}:policy/Titan"
        document = {
            "Statement": [
                {"Effect": "Allow", "Action": "bedrock:InvokeModel", "Resource": self.TITAN}
            ]
        }
        # The simulator sees the same permission, as it would for a real attached policy.
        iam = FakeIam(
            [allow(["bedrock:InvokeModel"], [self.TITAN])], managed={policy_arn: document}
        )

        result = evaluate(iam, attached_policy_arns=(policy_arn,))

        assert result.grant == "scoped"

    def test_a_named_model_that_is_denied_without_an_explicit_deny_is_unknown_not_none(self):
        """A boundary hides the Allow from the simulator; 'none' would be a false all-clear."""
        iam = FakeIam([allow(["bedrock:InvokeModel"], [self.TITAN])], boundary=[allow(["s3:*"])])

        result = evaluate(iam)

        assert result.grant == "unknown"
        assert result.regions_allowed == ()
        assert any("Review it manually" in w for w in result.warnings)
        assert any(
            r.resource == self.TITAN and r.decision == "implicitDeny" for r in result.results
        )

    def test_a_named_model_with_an_explicit_deny_is_a_definite_none(self):
        iam = FakeIam(
            [
                allow(["bedrock:InvokeModel"], [self.TITAN]),
                deny(["bedrock:InvokeModel"], [self.TITAN]),
            ]
        )

        result = evaluate(iam)

        assert result.grant == "none"
        assert not any("Review it manually" in w for w in result.warnings)

    def test_no_named_resources_and_no_access_is_still_none(self):
        assert evaluate(FakeIam([allow(["s3:*"])])).grant == "none"

    def test_a_resource_star_grant_needs_no_policy_reads(self):
        iam = FakeIam([allow(["bedrock:InvokeModel"])])

        assert evaluate(iam).grant == "broad"
        assert iam.policy_reads == 0

    def test_the_number_of_extra_probes_is_capped_and_says_so(self):
        arns = [
            f"arn:aws:bedrock:us-east-1::foundation-model/vendor.model-{i}-v1:0" for i in range(300)
        ]
        iam = FakeIam([allow(["bedrock:InvokeModel"], arns)])

        result = evaluate(iam)

        assert any("more Amazon Bedrock resources than the 120" in w for w in result.warnings)
        probed = {c_arn for c in iam.calls for c_arn in c.get("ResourceArns", [])}
        assert len([a for a in probed if "vendor.model-" in a]) == 120

    def test_a_policy_that_names_only_a_resource_type_wildcard_cannot_be_probed(self):
        """arn:aws:bedrock:*:*:* has no resource type to fill in, so it is left to the sample."""
        iam = FakeIam([allow(["bedrock:InvokeModel"], ["arn:aws:bedrock:*:*:*"])])

        result = evaluate(iam)

        assert result.grant == "broad"  # the bundled sample matches it everywhere
