# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Pin the evaluator to the real SimulatePrincipalPolicy response shape, via botocore's own
service model (the Stubber rejects responses that do not validate against it)."""

from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.evaluator import SimulatorEvaluator
from bedrock_permissions_audit.models import Principal

ARN = "arn:aws:iam::123456789012:user/alice"


def make_principal():
    return Principal(account_id="123456789012", name="alice", arn=ARN)


def test_parses_single_resource_result_with_matched_statements_and_missing_context(
    stubbed_session,
):
    config = Config(
        invoke_actions=("bedrock:InvokeModel",), escalation_actions=(), canary_actions=()
    )
    stubbed_session.stubber("iam").add_response(
        "simulate_principal_policy",
        {
            "EvaluationResults": [
                {
                    "EvalActionName": "bedrock:InvokeModel",
                    "EvalResourceName": "*",
                    "EvalDecision": "allowed",
                    "MatchedStatements": [
                        {
                            "SourcePolicyId": "BedrockInvoke",
                            "SourcePolicyType": "IAM Policy",
                            "StartPosition": {"Line": 4, "Column": 17},
                            "EndPosition": {"Line": 9, "Column": 6},
                        }
                    ],
                    "MissingContextValues": ["aws:SourceIp"],
                }
            ],
            "IsTruncated": False,
        },
        expected_params={"PolicySourceArn": ARN, "ActionNames": ["bedrock:InvokeModel"]},
    )

    result = SimulatorEvaluator(stubbed_session.client("iam"), config).evaluate(make_principal())

    (item,) = result.results
    assert item.decision == "allowed"
    assert item.matched_statements == ("BedrockInvoke (IAM Policy) line 4",)
    assert item.missing_context == ("aws:SourceIp",)
    assert result.grant == "broad"


def test_parses_resource_specific_results(stubbed_session):
    config = Config(
        invoke_actions=("bedrock:InvokeModel",),
        escalation_actions=(),
        canary_actions=(),
        bedrock_regions=("us-east-1",),
        representative_models=("anthropic.claude-3-haiku-20240307-v1:0",),
    )
    iam = stubbed_session.stubber("iam")
    iam.add_response(
        "simulate_principal_policy",
        {
            "EvaluationResults": [
                {
                    "EvalActionName": "bedrock:InvokeModel",
                    "EvalResourceName": "*",
                    "EvalDecision": "implicitDeny",
                }
            ],
            "IsTruncated": False,
        },
    )
    # With no broad grant the evaluator reads the user's own policies for the resources they name.
    iam.add_response(
        "list_user_policies",
        {"PolicyNames": [], "IsTruncated": False},
        expected_params={"UserName": "alice"},
    )
    haiku = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
    iam.add_response(
        "simulate_principal_policy",
        {
            "EvaluationResults": [
                {
                    "EvalActionName": "bedrock:InvokeModel",
                    "EvalResourceName": haiku,
                    "EvalDecision": "allowed",
                    "ResourceSpecificResults": [
                        {
                            "EvalResourceName": haiku,
                            "EvalResourceDecision": "allowed",
                            "MatchedStatements": [
                                {"SourcePolicyId": "OneModel", "SourcePolicyType": "IAM Policy"}
                            ],
                        },
                        {
                            "EvalResourceName": "arn:aws:bedrock:us-east-1:123456789012:"
                            "provisioned-model/audit-probe",
                            "EvalResourceDecision": "implicitDeny",
                        },
                    ],
                }
            ],
            "IsTruncated": False,
        },
    )

    result = SimulatorEvaluator(stubbed_session.client("iam"), config).evaluate(make_principal())

    allowed = [r for r in result.results if r.decision == "allowed"]
    assert [r.resource for r in allowed] == [haiku]
    assert allowed[0].matched_statements == ("OneModel (IAM Policy)",)
    assert result.grant == "scoped"
    assert result.regions_allowed == ("us-east-1",)
