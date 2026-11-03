# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Synth assertions for tasks.md 1.3, 1.4, 1.6, 1.7, 1.10 and the zero-ingress rule (D§11)."""

import json
import re


def _of(template, rtype):
    return [r for r in template["Resources"].values() if r["Type"] == rtype]


def test_parameters_timezone_required_and_handoff_rules(template):
    params = template["Parameters"]
    tz = params["ScheduleTimezone"]
    assert "Default" not in tz and re.fullmatch(tz["AllowedPattern"], "Europe/Berlin")
    assert not re.fullmatch(tz["AllowedPattern"], "CET; drop")
    for name in ("DevOpsAgentWebhookUrl", "WebhookSecretParameterName", "DevOpsAgentSpaceId"):
        assert params[name]["Default"] == ""
    assert re.fullmatch(params["DevOpsAgentWebhookUrl"]["AllowedPattern"],
                        "https://event-ai.eu-central-1.api.aws/webhook/generic/abc123")
    assert not re.fullmatch(params["DevOpsAgentWebhookUrl"]["AllowedPattern"], "http://evil.example.com/x")
    rules = template["Rules"]
    assert {"HandoffRequiresAllSettings", "HandoffDisabledRequiresNoSettings"} <= set(rules)
    assert len(rules["HandoffRequiresAllSettings"]["Assertions"]) == 3


def test_kms_key_rotation_and_cloudwatch_grant(template):
    (key,) = _of(template, "AWS::KMS::Key")
    assert key["Properties"]["EnableKeyRotation"] is True and key["DeletionPolicy"] == "Retain"
    principals = json.dumps(key["Properties"]["KeyPolicy"])
    assert "cloudwatch.amazonaws.com" in principals


def test_bucket_encrypted_versioned_private_tls_retained(template):
    (bucket,) = _of(template, "AWS::S3::Bucket")
    p = bucket["Properties"]
    assert p["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]["ServerSideEncryptionByDefault"][
        "SSEAlgorithm"] == "aws:kms"
    assert p["VersioningConfiguration"]["Status"] == "Enabled"
    assert all(p["PublicAccessBlockConfiguration"].values())
    assert bucket["DeletionPolicy"] == "Retain"
    (policy,) = _of(template, "AWS::S3::BucketPolicy")
    assert "aws:SecureTransport" in json.dumps(policy)


def test_table_cmk_pitr_gsi_ttl_retained(template):
    (table,) = _of(template, "AWS::DynamoDB::Table")
    p = table["Properties"]
    assert p["SSESpecification"]["SSEType"] == "KMS" and p["SSESpecification"]["SSEEnabled"] is True
    assert p["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
    assert p["GlobalSecondaryIndexes"][0]["IndexName"] == "status-index"
    assert p["TimeToLiveSpecification"] == {"AttributeName": "ttl", "Enabled": True}
    assert table["DeletionPolicy"] == "Retain"
    assert {"Key": "agent-managed", "Value": "true"} in p["Tags"]


def test_cloudwatch_alarms_may_publish_to_topic(template):
    """Regression (2026-10-14): without this Allow, every alarm action failed silently."""
    (policy,) = _of(template, "AWS::SNS::TopicPolicy")
    allows = [s for s in policy["Properties"]["PolicyDocument"]["Statement"] if s["Effect"] == "Allow"]
    (grant,) = [s for s in allows if s.get("Principal") == {"Service": "cloudwatch.amazonaws.com"}]
    assert grant["Action"] == "sns:Publish"
    assert "aws:SourceAccount" in json.dumps(grant["Condition"]) and "aws:SourceArn" in json.dumps(grant["Condition"])
    # no unconditioned public grant
    assert not [s for s in allows if s.get("Principal") in ("*", {"AWS": "*"})]


def test_topic_encrypted_and_email_conditional(template):
    (topic,) = _of(template, "AWS::SNS::Topic")
    assert "KmsMasterKeyId" in topic["Properties"]
    (sub,) = _of(template, "AWS::SNS::Subscription")
    assert sub["Condition"] == "HasNotificationEmail"


def test_lambdas_arm64_python312_tracing_scoped_logs(template):
    functions = _of(template, "AWS::Lambda::Function")
    assert len(functions) == 10  # 6 checker + batch, investigate, merge, callback
    for fn in functions:
        p = fn["Properties"]
        assert p["Runtime"] == "python3.12" and p["Architectures"] == ["arm64"]
        assert p["TracingConfig"]["Mode"] == "Active" and p["MemorySize"] == 512
        assert "LoggingConfig" in p
    for lg in _of(template, "AWS::Logs::LogGroup"):
        assert lg["Properties"]["RetentionInDays"] == {"Ref": "LogRetentionDays"}


def test_zero_ingress(template):
    forbidden = re.compile(r"^AWS::(Lambda::Url|ApiGateway|ApiGatewayV2|ElasticLoadBalancingV2|EC2::SecurityGroup)")
    assert [r["Type"] for r in template["Resources"].values() if forbidden.match(r["Type"])] == []
    # Only the callback has a resource policy, and only in a hand-off shape (D§11). Same-account
    # uses the legacy AWS::Lambda::Permission (the caller is an AWS service principal, so
    # SourceArn/SourceAccount apply); cross-account uses AWS::Lambda::ResourcePolicy (the caller
    # is a cross-account IAM role, which needs the full condition-key range via aws:PrincipalArn
    # -- AWS::Lambda::Permission's SourceArn/SourceAccount only apply to service principals).
    # Deliberately two different resource types, not one: CloudFormation docs warn that mixing
    # AWS::Lambda::Permission and AWS::Lambda::ResourcePolicy on the SAME function can silently
    # overwrite statements, so this project never puts both on the callback for the same
    # condition. SameAccountHandoff / CrossAccountHandoff are mutually exclusive, so only one of
    # the two ever actually applies in a given deployment.
    permissions = {lid: r for lid, r in template["Resources"].items() if r["Type"] == "AWS::Lambda::Permission"}
    assert {p["Condition"] for p in permissions.values()} == {"SameAccountHandoff"}
    for p in permissions.values():
        assert "CallbackFunction" in json.dumps(p["Properties"]["FunctionName"])
    resource_policies = {lid: r for lid, r in template["Resources"].items()
                          if r["Type"] == "AWS::Lambda::ResourcePolicy"}
    assert {p["Condition"] for p in resource_policies.values()} == {"CrossAccountHandoff"}
    for p in resource_policies.values():
        assert "CallbackFunction" in json.dumps(p["Properties"]["ResourceArn"])


def test_state_machine_shape(template):
    (sm,) = _of(template, "AWS::StepFunctions::StateMachine")
    p = sm["Properties"]
    assert p["TracingConfiguration"]["Enabled"] is True
    assert p["LoggingConfiguration"]["IncludeExecutionData"] is False
    definition = json.dumps(p["DefinitionString"])
    for state in ("Init", "HasCloudWan?", "CollectCloudWan", "CloudWanNotEvaluated", "CollectRegions",
                  "RegionNotEvaluated", "Evaluate", "Diff", "Report", "Publish", "AdvanceMarker?", "UpdateMarker"):
        assert f'\\"{state}\\"' in definition, state
    assert "MaxConcurrencyPath" in definition and "TimeoutSeconds" in definition


def test_schedule_uses_timezone_and_scoped_role(template):
    (schedule,) = _of(template, "AWS::Scheduler::Schedule")
    p = schedule["Properties"]
    assert p["ScheduleExpressionTimezone"] == {"Ref": "ScheduleTimezone"}
    assert p["FlexibleTimeWindow"] == {"Mode": "OFF"} and p["Target"]["Input"] == "{}"


def test_alarms_wired_to_topic(template):
    alarms = _of(template, "AWS::CloudWatch::Alarm")
    # failed, missed run, regions not evaluated, investigation failed, callback DLQ,
    # 6 x checker-function error rate (D§9)
    assert len(alarms) == 11
    topic_id = next(lid for lid, r in template["Resources"].items() if r["Type"] == "AWS::SNS::Topic")
    assert all(a["Properties"]["AlarmActions"] == [{"Ref": topic_id}] for a in alarms)
    missed = next(a for a in alarms if "26 hours" in a["Properties"]["AlarmDescription"])
    assert missed["Properties"]["TreatMissingData"] == "breaching"
    assert missed["Properties"]["EvaluationPeriods"] == 26 and missed["Properties"]["Period"] == 3600
    # Regression (2026-10-14): a sliding window kept re-using yesterday's datapoint and never fired.
    assert missed["Properties"]["EvaluationWindow"] == {"WallClockWindow": {"Timezone": "UTC"}}


# --- Phase 3: hand-off (tasks.md 3.4, 3.6, 3.12, 3.13) ---------------------------------------

def _asl(template):
    """The state machine definition as a dict, with CloudFormation refs replaced by placeholders."""
    (sm,) = _of(template, "AWS::StepFunctions::StateMachine")
    parts = sm["Properties"]["DefinitionString"]["Fn::Join"][1]
    text = ""
    for part in parts:
        if isinstance(part, str):
            text += part
        elif "Ref" in part and part["Ref"].startswith("Investigation"):
            text += "900"  # numeric parameters land unquoted
        else:
            text += "REF"
    return json.loads(text)


def _by_id(template, prefix):
    (item,) = [r for lid, r in template["Resources"].items() if lid.startswith(prefix)]
    return item


def test_investigation_branch_shape(template):
    states = _asl(template)["States"]
    choice = states["HasNewAndHandoff?"]
    (when,) = choice["Choices"]
    assert when["And"] == [{"Variable": "$.init.handoff_enabled", "BooleanEquals": True},
                           {"Variable": "$.diff.new_drift", "NumericGreaterThan": 0}]
    assert when["Next"] == "BatchFindings" and choice["Default"] == "SkipInvestigation"
    assert states["Diff"]["Next"] == "HasNewAndHandoff?"
    assert states["SkipInvestigation"] == {"Type": "Pass", "Result": {"status": "skipped"},
                                           "ResultPath": "$.investigation", "Next": "Report"}
    assert states["BatchFindings"]["Next"] == "InvestigateBatches"
    assert states["MergeInvestigations"]["Next"] == "Report"
    assert states["MergeInvestigations"]["ResultPath"] == "$.investigation"
    assert states["Report"]["Parameters"]["investigation.$"] == "$.investigation"


def test_investigate_map_iteration(template):
    m = _asl(template)["States"]["InvestigateBatches"]
    assert m["ItemsPath"] == "$.batches.batches" and m["ResultPath"] == "$.investigations"
    assert m["MaxConcurrency"] == 900 and m["Next"] == "MergeInvestigations"  # placeholder for the Ref
    assert m["ItemSelector"]["batch_n.$"] == "$$.Map.Item.Value.batch_n"
    task = m["ItemProcessor"]["States"]["InvestigateBatch"]
    assert task["Resource"].endswith(":states:::lambda:invoke.waitForTaskToken")
    assert task["Parameters"]["Payload"]["task_token.$"] == "$$.Task.Token"
    assert task["ResultPath"] == "$.result"  # not null: Merge reads it (tasks.md 3.2 As built)
    assert task["TimeoutSeconds"] == 900 and task["HeartbeatSeconds"] == 900
    retries = {tuple(r["ErrorEquals"]): r for r in task["Retry"]}
    assert retries[("WebhookServerError", "WebhookTimeout", "WebhookTransportError")]["MaxAttempts"] == 2
    assert not any("WebhookConfigError" in e or "WebhookClientError" in e for e in retries)
    (catch,) = task["Catch"]
    assert catch == {"ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": "MarkBatchFailed"}
    assert m["ItemProcessor"]["States"]["MarkBatchFailed"]["Type"] == "Pass"
    # Both timeouts come from the stack parameters.
    (sm,) = _of(template, "AWS::StepFunctions::StateMachine")
    refs = json.dumps(sm["Properties"]["DefinitionString"])
    for name in ("InvestigationTimeoutSeconds", "InvestigationHeartbeatSeconds", "InvestigationConcurrency"):
        assert f'{{"Ref": "{name}"}}' in refs


def test_handoff_conditions_cover_three_shapes(template):
    conditions = template["Conditions"]
    assert conditions["HandoffEnabled"] == {"Fn::Equals": [{"Ref": "EnableDevOpsAgentHandoff"}, "true"]}
    same, cross = json.dumps(conditions["SameAccountHandoff"]), json.dumps(conditions["CrossAccountHandoff"])
    assert '"Fn::Not"' in same and "DevOpsAgentAccountId" in same and "AWS::AccountId" in same
    assert "DevOpsAgentAccountId" in cross and "AWS::AccountId" in cross
    assert re.fullmatch(template["Parameters"]["DevOpsAgentAccountId"]["AllowedPattern"], "210987654321")
    assert not re.fullmatch(template["Parameters"]["DevOpsAgentAccountId"]["AllowedPattern"], "12345")


def test_same_account_rule_pattern_filter_and_permission(template):
    rule = _by_id(template, "InvestigationEventsRule")
    assert rule["Condition"] == "SameAccountHandoff"
    pattern = rule["Properties"]["EventPattern"]
    assert pattern["source"] == ["aws.aidevops"]
    assert len(pattern["detail-type"]) == 9 and "Investigation Linked" in pattern["detail-type"]
    assert pattern["detail"] == {"metadata": {"agent_space_id": [{"Ref": "DevOpsAgentSpaceId"}]}}
    (target,) = rule["Properties"]["Targets"]
    assert "CallbackFunction" in json.dumps(target["Arn"]) and "RoleArn" not in target
    perm = _by_id(template, "CallbackFromRule")["Properties"]
    assert perm["Principal"] == "events.amazonaws.com" and "InvestigationEventsRule" in json.dumps(perm["SourceArn"])
    assert perm["SourceAccount"] == {"Ref": "AWS::AccountId"}


def test_cross_account_permission_is_scoped_to_the_forwarder_role(template):
    """The cross-account grant must name the exact forwarder-role ARN, not just the account (the
    pre-release security scan HIGH finding this fixes: a bare account principal admits every IAM principal in that
    account, not just the intended event-forwarder role)."""
    policy = _by_id(template, "CallbackFromAgentSpaceAccount")
    assert policy["Type"] == "AWS::Lambda::ResourcePolicy"
    assert policy["Condition"] == "CrossAccountHandoff"
    (statement,) = policy["Properties"]["PolicyDocument"]["Statement"]
    assert statement["Effect"] == "Allow" and statement["Action"] == "lambda:InvokeFunction"
    principal_parts = ["arn:", {"Ref": "AWS::Partition"}, ":iam::", {"Ref": "DevOpsAgentAccountId"}, ":root"]
    assert statement["Principal"] == {"AWS": {"Fn::Join": ["", principal_parts]}}
    condition_text = json.dumps(statement["Condition"])
    assert "aws:PrincipalArn" in condition_text
    assert "nrdc-event-forwarder-" in condition_text
    # Not just the account ID: the condition must name the role, which a bare account-ID
    # principal (the old, vulnerable shape) could never do.
    assert "DevOpsAgentAccountId" in condition_text


def _conditional_policy(template, prefix):
    policy = _by_id(template, prefix)
    (st,) = policy["Properties"]["PolicyDocument"]["Statement"]
    return policy.get("Condition"), st


def test_shape_specific_grants_are_conditional(template):
    cond, st = _conditional_policy(template, "CallbackJournalPolicy")
    assert cond == "SameAccountHandoff" and st["Action"] == "aidevops:ListJournalRecords"
    cond, st = _conditional_policy(template, "CallbackAssumeJournalReaderPolicy")
    assert cond == "CrossAccountHandoff" and st["Action"] == "sts:AssumeRole"
    assert "nrdc-journal-reader-" in json.dumps(st["Resource"])
    cond, st = _conditional_policy(template, "InvestigateSecretPolicy")
    assert cond == "HandoffEnabled" and st["Action"] == "ssm:GetParameter"
    # Nothing shape-specific leaks into the always-present default policies.
    for lid, res in template["Resources"].items():
        if res["Type"] == "AWS::IAM::Policy" and "Condition" not in res:
            text = json.dumps(res["Properties"]["PolicyDocument"])
            assert "aidevops:" not in text and "sts:AssumeRole" not in text and "ssm:GetParameter" not in text, lid


def test_send_task_grant_is_scoped_to_the_state_machine(template):
    statements = [st for r in _of(template, "AWS::IAM::Policy")
                  for st in r["Properties"]["PolicyDocument"]["Statement"]
                  if "states:SendTaskSuccess" in json.dumps(st["Action"])]
    (st,) = statements
    assert sorted(st["Action"]) == ["states:SendTaskFailure", "states:SendTaskHeartbeat", "states:SendTaskSuccess"]
    assert st["Resource"] == {"Ref": next(lid for lid, r in template["Resources"].items()
                                          if r["Type"] == "AWS::StepFunctions::StateMachine")}


def test_callback_dlq_encrypted_and_wired(template):
    (queue,) = _of(template, "AWS::SQS::Queue")
    assert "KmsMasterKeyId" in queue["Properties"]
    (config,) = _of(template, "AWS::Lambda::EventInvokeConfig")
    p = config["Properties"]
    assert p["MaximumRetryAttempts"] == 2 and "CallbackDlq" in json.dumps(p["DestinationConfig"])
    assert "CallbackFunction" in json.dumps(p["FunctionName"])
    descriptions = [a["Properties"]["AlarmDescription"] for a in _of(template, "AWS::CloudWatch::Alarm")]
    assert any("investigation batch failed" in d for d in descriptions)
    assert any("could not be processed by the callback" in d for d in descriptions)


def test_outputs_for_the_companion_stack(template):
    assert {"CallbackFunctionArn", "CallbackRoleArn"} <= set(template["Outputs"])


# --- Companion stack (D§3.3a) -------------------------------------------------------------------

def test_link_stack_contents(link_template):
    types = sorted(r["Type"] for r in link_template["Resources"].values() if r["Type"] != "AWS::CDK::Metadata")
    assert types == ["AWS::Events::Rule", "AWS::IAM::Policy", "AWS::IAM::Policy", "AWS::IAM::Role", "AWS::IAM::Role"]


def test_link_rule_targets_callback_with_forwarder_role(link_template):
    rule = _by_id(link_template, "InvestigationEventsRule")["Properties"]
    assert rule["Name"] == "nrdc-devops-agent-investigation-events"
    assert rule["EventPattern"]["source"] == ["aws.aidevops"] and len(rule["EventPattern"]["detail-type"]) == 9
    assert rule["EventPattern"]["detail"] == {"metadata": {"agent_space_id": [{"Ref": "DevOpsAgentSpaceId"}]}}
    (target,) = rule["Targets"]
    assert target["Arn"] == {"Ref": "CallbackFunctionArn"} and "EventForwarderRole" in json.dumps(target["RoleArn"])


def _role(link_template, prefix):
    (role,) = [r for lid, r in link_template["Resources"].items()
               if lid.startswith(prefix) and r["Type"] == "AWS::IAM::Role"]
    return role["Properties"]


def test_link_role_names_match_the_python_format(link_template):
    from drift_core.cross_account import EVENT_FORWARDER_ROLE_FORMAT, JOURNAL_READER_ROLE_FORMAT

    for prefix, fmt in (("EventForwarderRole", EVENT_FORWARDER_ROLE_FORMAT),
                        ("JournalReaderRole", JOURNAL_READER_ROLE_FORMAT)):
        parts = _role(link_template, prefix)["RoleName"]["Fn::Join"][1]
        assert parts == [fmt.split("{")[0], {"Ref": "CheckerAccountId"}, "-", {"Ref": "AWS::Region"}]


def test_link_forwarder_trust_and_permission(link_template):
    trust = _role(link_template, "EventForwarderRole")["AssumeRolePolicyDocument"]["Statement"]
    (st,) = trust
    assert st["Principal"] == {"Service": "events.amazonaws.com"}
    cond = json.dumps(st["Condition"])
    assert "aws:SourceAccount" in cond and "nrdc-devops-agent-investigation-events" in cond


def test_link_journal_reader_trust_is_pinned_to_the_callback_role(link_template):
    (st,) = _role(link_template, "JournalReaderRole")["AssumeRolePolicyDocument"]["Statement"]
    assert "CheckerAccountId" in json.dumps(st["Principal"])
    assert st["Condition"] == {"ArnEquals": {"aws:PrincipalArn": {"Ref": "CallbackRoleArn"}}}


def test_link_stack_parameters_are_validated(link_template):
    params = link_template["Parameters"]
    assert re.fullmatch(params["CallbackFunctionArn"]["AllowedPattern"],
                        "arn:aws:lambda:us-east-1:123456789012:function:NetworkRoutingDriftChecker-Callback-abc")
    assert not re.fullmatch(params["CallbackFunctionArn"]["AllowedPattern"], "arn:aws:lambda:us-east-1:5791:function:x")
    assert re.fullmatch(params["CheckerAccountId"]["AllowedPattern"], "123456789012")
