# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the read-only AWS discovery adapter.

These tests never import boto3/botocore. A FakeClientFactory below stands in
for AWS entirely, so discovery logic (presence detection, permission-denial
handling, graceful degradation) is testable without any AWS credentials or
network access, per the project's "tests use synthetic fixtures and mocked
adapters" rule.
"""

import unittest
from typing import Any

from src.assessment_core import Scope, assess_payload
from src.discovery import (
    ENHANCED_READ_ONLY_ACTIONS,
    MINIMUM_READ_ONLY_ACTIONS,
    run_aws_discovery,
)


class FakeClientError(Exception):
    """Stand-in for botocore.exceptions.ClientError with a matching .response shape."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeClient:
    """A single fake AWS service client whose methods return canned responses.

    `responses` maps method name -> return value OR an exception instance to
    raise. This mirrors how a real botocore client would behave on success vs
    ClientError, without needing botocore installed.
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses

    def __getattr__(self, name: str) -> Any:
        if name not in self._responses:
            raise AssertionError(f"Unexpected call to unmocked method {name}")
        value = self._responses[name]

        def _method(**kwargs: Any) -> Any:
            if isinstance(value, Exception):
                raise value
            if callable(value):
                return value(**kwargs)
            return value

        return _method


class FakeClientFactory:
    """Fake ClientFactory protocol implementation for discovery tests.

    `services` maps service name -> FakeClient. Any service not present
    raises AssertionError, so tests fail loudly if discovery calls an
    unexpected service rather than silently returning None everywhere.
    """

    def __init__(self, services: dict[str, FakeClient]) -> None:
        self._services = services

    def client(self, service_name: str) -> Any:
        if service_name not in self._services:
            raise AssertionError(f"Unexpected client() call for service {service_name}")
        return self._services[service_name]


def _minimal_factory(overrides: dict[str, dict[str, Any]] | None = None) -> FakeClientFactory:
    """Build a factory where every discovery call succeeds with empty results.

    `overrides` lets a test replace specific service/method responses while
    keeping every other call passing with an empty/negative result, so each
    test only has to describe the one thing it cares about.
    """

    overrides = overrides or {}

    def merged(service: str, defaults: dict[str, Any]) -> FakeClient:
        return FakeClient({**defaults, **overrides.get(service, {})})

    return FakeClientFactory(
        {
            "sts": merged(
                "sts", {"get_caller_identity": {"Arn": "arn:aws:iam::123456789012:role/Test"}}
            ),
            "iam": merged("iam", {"simulate_principal_policy": {"EvaluationResults": []}}),
            "cloudformation": merged("cloudformation", {"list_stacks": {"StackSummaries": []}}),
            "resourcegroupstaggingapi": merged(
                "resourcegroupstaggingapi",
                {
                    "get_tag_keys": {"TagKeys": []},
                    "get_resources": {"ResourceTagMappingList": []},
                },
            ),
            "ec2": merged(
                "ec2",
                {
                    "describe_vpcs": {"Vpcs": []},
                    "describe_security_groups": {"SecurityGroups": []},
                    "describe_instances": {"Reservations": []},
                },
            ),
            "organizations": merged("organizations", {"list_accounts": {"Accounts": []}}),
            "lambda": merged("lambda", {"list_functions": {"Functions": []}}),
            "ecs": merged("ecs", {"list_clusters": {"clusterArns": []}}),
            "eks": merged("eks", {"list_clusters": {"clusters": []}}),
            "dynamodb": merged(
                "dynamodb",
                {"list_tables": {"TableNames": []}, "describe_table": {"Table": {"KeySchema": []}}},
            ),
            "rds": merged("rds", {"describe_db_instances": {"DBInstances": []}}),
            "s3": merged("s3", {"list_buckets": {"Buckets": []}}),
            "cognito-idp": merged("cognito-idp", {"list_user_pools": {"UserPools": []}}),
            "secretsmanager": merged("secretsmanager", {"list_secrets": {"SecretList": []}}),
            "cloudwatch": merged(
                "cloudwatch",
                {
                    "describe_alarms": {"MetricAlarms": [], "CompositeAlarms": []},
                    "list_metrics": {"Metrics": []},
                },
            ),
            "logs": merged("logs", {"describe_log_groups": {"logGroups": []}}),
            "ce": merged("ce", {"get_cost_and_usage": {"ResultsByTime": []}}),
            # Edge tier (per-tenant routing signals). Defaults return empty so
            # edge discovery is a no-op unless a test overrides these.
            "cloudfront": merged("cloudfront", {"list_distributions": {"DistributionList": {"Items": []}}}),
            "acm": merged("acm", {"list_certificates": {"CertificateSummaryList": []}}),
            "wafv2": merged("wafv2", {"list_web_acls": {"WebACLs": []}}),
            "bedrock-agentcore-control": merged(
                "bedrock-agentcore-control",
                {"list_agent_runtimes": {"agentRuntimes": []}, "list_gateways": {"items": []}},
            ),
            "s3vectors": merged(
                "s3vectors",
                {"list_vector_buckets": {"vectorBuckets": []}, "list_indexes": {"indexes": []}},
            ),
        }
    )


class DiscoveryTests(unittest.TestCase):
    def test_minimum_mode_never_calls_organizations_or_cost_explorer(self):
        # Minimum mode must not attempt organizations:* or ce:* at all,
        # because those actions are not in MINIMUM_READ_ONLY_ACTIONS and a
        # real account without org/billing access would just get denied.
        factory = FakeClientFactory(
            {
                "sts": FakeClient(
                    {"get_caller_identity": {"Arn": "arn:aws:iam::123456789012:role/Test"}}
                ),
                "iam": FakeClient({"simulate_principal_policy": {"EvaluationResults": []}}),
                "cloudformation": FakeClient({"list_stacks": {"StackSummaries": []}}),
                "resourcegroupstaggingapi": FakeClient(
                    {
                        "get_tag_keys": {"TagKeys": []},
                        "get_resources": {"ResourceTagMappingList": []},
                    }
                ),
                "ec2": FakeClient(
                    {
                        "describe_vpcs": {"Vpcs": []},
                        "describe_security_groups": {"SecurityGroups": []},
                        "describe_instances": {"Reservations": []},
                    }
                ),
                "lambda": FakeClient({"list_functions": {"Functions": []}}),
                "ecs": FakeClient({"list_clusters": {"clusterArns": []}}),
                "eks": FakeClient({"list_clusters": {"clusters": []}}),
                "dynamodb": FakeClient({"list_tables": {"TableNames": []}}),
                "rds": FakeClient({"describe_db_instances": {"DBInstances": []}}),
                "s3": FakeClient({"list_buckets": {"Buckets": []}}),
                "cognito-idp": FakeClient({"list_user_pools": {"UserPools": []}}),
                "secretsmanager": FakeClient({"list_secrets": {"SecretList": []}}),
                "cloudwatch": FakeClient(
                    {
                        "describe_alarms": {"MetricAlarms": [], "CompositeAlarms": []},
                        "list_metrics": {"Metrics": []},
                    }
                ),
                "logs": FakeClient({"describe_log_groups": {"logGroups": []}}),
                "cloudfront": FakeClient({"list_distributions": {"DistributionList": {"Items": []}}}),
                "acm": FakeClient({"list_certificates": {"CertificateSummaryList": []}}),
                "wafv2": FakeClient({"list_web_acls": {"WebACLs": []}}),
                "bedrock-agentcore-control": FakeClient(
                    {"list_agent_runtimes": {"agentRuntimes": []}, "list_gateways": {"items": []}}
                ),
                "s3vectors": FakeClient(
                    {"list_vector_buckets": {"vectorBuckets": []}, "list_indexes": {"indexes": []}}
                ),
                # organizations and ce deliberately absent: calling them
                # would raise AssertionError, proving minimum mode skips them.
            }
        )
        scope = Scope(access_mode="minimum_read_only")
        facts, evidence, observations = run_aws_discovery(scope, client_factory=factory)

        self.assertNotIn("multi_account_org", facts.get("signals", {}))
        self.assertEqual((), evidence)

    def test_enhanced_mode_calls_organizations_and_cost_explorer(self):
        factory = _minimal_factory(
            {
                "organizations": {
                    "list_accounts": {"Accounts": [{"Id": "1"}, {"Id": "2"}, {"Id": "3"}]}
                },
            }
        )
        scope = Scope(access_mode="enhanced_assessment")
        facts, _evidence, observations = run_aws_discovery(scope, client_factory=factory)

        self.assertTrue(facts["signals"]["multi_account_org"]["detected"])
        self.assertEqual(3, facts["signals"]["multi_account_org"]["account_count"])
        self.assertTrue(any("3 member accounts" in obs for obs in observations))

    def test_edge_presence_detects_cloudfront_acm_and_waf_signals(self):
        # Per-tenant edge signals: CloudFront distributions + ACM certs + WAF
        # should populate services and set the edge_multi_tenancy signal
        # (suggestive, never confirmed).
        factory = _minimal_factory(
            {
                "cloudfront": {
                    "list_distributions": {
                        "DistributionList": {"Items": [{"Id": "E1"}, {"Id": "E2"}]}
                    }
                },
                "acm": {
                    "list_certificates": {
                        "CertificateSummaryList": [{"CertificateArn": "arn:aws:acm:...:c1"}]
                    }
                },
                "wafv2": {"list_web_acls": {"WebACLs": [{"Name": "edge-acl"}]}},
            }
        )
        facts, _evidence, observations = run_aws_discovery(
            Scope(access_mode="minimum_read_only"), client_factory=factory
        )

        signal = facts["signals"]["edge_multi_tenancy"]
        self.assertTrue(signal["detected"])
        self.assertFalse(signal["confirmed"])
        self.assertEqual(2, signal["distribution_count"])
        self.assertEqual(1, signal["acm_certificate_count"])
        self.assertTrue(signal["edge_waf_detected"])
        self.assertIn("cloudfront", facts["services"])
        self.assertIn("acm", facts["services"])
        self.assertIn("waf", facts["services"])
        self.assertTrue(any("CloudFront distribution" in obs for obs in observations))

    def test_agentic_signals_detect_agentcore_and_per_tenant_vector_memory(self):
        factory = _minimal_factory(
            {
                "bedrock-agentcore-control": {
                    "list_agent_runtimes": {"agentRuntimes": [{"agentRuntimeId": "rt-1"}]},
                    "list_gateways": {"items": [{"gatewayId": "gw-1"}]},
                },
                "s3vectors": {
                    "list_vector_buckets": {"vectorBuckets": [{"vectorBucketName": "agent-memory"}]},
                    "list_indexes": {"indexes": [{"indexName": "memory-tenant-001"}]},
                },
            }
        )
        facts, _evidence, observations = run_aws_discovery(
            Scope(access_mode="minimum_read_only"), client_factory=factory
        )
        signals = facts["signals"]
        self.assertTrue(signals["agentic_platform"]["detected"])
        self.assertEqual(signals["agentic_platform"]["agent_runtime_count"], 1)
        self.assertEqual(signals["agentic_platform"]["gateway_count"], 1)
        # per-tenant vector index -> suggestive (detected, not confirmed) TAI-03 signal
        self.assertTrue(signals["agent_memory_isolation"]["detected"])
        self.assertFalse(signals["agent_memory_isolation"]["confirmed"])
        self.assertIn("bedrock-agentcore", facts["services"])
        self.assertIn("s3vectors", facts["services"])
        self.assertTrue(any("AgentCore" in obs for obs in observations))

    def test_agentic_probe_absent_services_emit_no_signal_no_penalty(self):
        # Services reachable but empty -> no agentic signals emitted at all, so a
        # non-agentic (or differently-isolated) SaaS is never penalized on TAI-03.
        facts, _evidence, _observations = run_aws_discovery(
            Scope(access_mode="minimum_read_only"), client_factory=_minimal_factory()
        )
        self.assertNotIn("agent_memory_isolation", facts["signals"])
        self.assertNotIn("agentic_platform", facts["signals"])

    def test_denied_permission_becomes_unknown_evidence_not_crash(self):
        factory = _minimal_factory(
            {
                "iam": {
                    "simulate_principal_policy": {
                        "EvaluationResults": [
                            {
                                "EvalActionName": "ce:GetCostAndUsage",
                                "EvalDecision": "explicitDeny",
                            },
                        ]
                    }
                },
            }
        )
        scope = Scope(access_mode="minimum_read_only")
        facts, evidence, _observations = run_aws_discovery(scope, client_factory=factory)

        self.assertIn("ce:GetCostAndUsage", facts.get("missing_permissions", []))
        control_ids = {item.control_id for item in evidence}
        self.assertIn("CAM-01", control_ids)
        self.assertTrue(all(item.status == "unknown" for item in evidence))

    def test_client_error_during_call_degrades_gracefully(self):
        factory = _minimal_factory({"lambda": {"list_functions": FakeClientError("AccessDenied")}})
        scope = Scope(access_mode="minimum_read_only")
        facts, evidence, _observations = run_aws_discovery(scope, client_factory=factory)

        # A denial mid-pipeline should not raise and should not stop later
        # discovery steps (ecs, eks, etc. still get called).
        self.assertIsInstance(facts, dict)
        self.assertTrue(any(item.evidence_state == "unknown" for item in evidence))

    def test_dynamodb_tenant_shaped_partition_key_is_suggestive_not_confirmed(self):
        factory = _minimal_factory(
            {
                "dynamodb": {
                    "list_tables": {"TableNames": ["orders"]},
                    "describe_table": {
                        "Table": {"KeySchema": [{"AttributeName": "tenant_id", "KeyType": "HASH"}]}
                    },
                }
            }
        )
        scope = Scope(access_mode="minimum_read_only")
        facts, _evidence, _observations = run_aws_discovery(scope, client_factory=factory)

        signal = facts["signals"]["tenant_registry"]
        self.assertTrue(signal["detected"])
        self.assertFalse(signal["confirmed"])  # naming alone is never confirmed evidence
        self.assertIn("dynamodb", facts.get("services", []))

    def test_lambda_and_ecs_presence_populate_services(self):
        factory = _minimal_factory(
            {
                "lambda": {"list_functions": {"Functions": [{"FunctionName": "f1"}]}},
                "ecs": {
                    "list_clusters": {
                        "clusterArns": ["arn:aws:ecs:us-east-1:123456789012:cluster/c1"]
                    }
                },
            }
        )
        scope = Scope(access_mode="minimum_read_only")
        facts, _evidence, _observations = run_aws_discovery(scope, client_factory=factory)

        self.assertIn("lambda", facts.get("services", []))
        self.assertIn("ecs", facts.get("services", []))

    def test_action_lists_stay_read_only(self):
        # Defensive test against accidental regression: none of the actions
        # this module can request may be a mutating verb. This mirrors the
        # BLOCKED-by-default verbs in iam-permission-boundary.md.
        blocked_verbs = (
            "Create",
            "Delete",
            "Update",
            "Put",
            "Start",
            "Stop",
            "Terminate",
            "Modify",
            "Attach",
            "Detach",
            "Reboot",
            "Run",
            "Authorize",
            "Revoke",
        )
        # IAM action names lead with their verb, so check the prefix: a
        # substring check would wrongly reject e.g. ListAgentRuntimes ("Run").
        read_only_verbs = ("Describe", "List", "Get", "Simulate", "GET")
        for action in ENHANCED_READ_ONLY_ACTIONS:
            name = action.split(":")[1] if ":" in action else action
            with self.subTest(action=action):
                self.assertFalse(
                    name.startswith(blocked_verbs),
                    f"{action} looks like a mutating action; must not be read-only-listed",
                )
                self.assertTrue(
                    name.startswith(read_only_verbs),
                    f"{action} does not start with a read-only verb",
                )

    def test_minimum_actions_are_a_subset_of_enhanced_actions(self):
        self.assertTrue(set(MINIMUM_READ_ONLY_ACTIONS).issubset(set(ENHANCED_READ_ONLY_ACTIONS)))

    def test_missing_boto3_degrades_to_single_unknown_evidence(self):
        # client_factory=None with boto3 uninstalled/unavailable should not
        # raise; run_aws_discovery must catch ModuleNotFoundError internally.
        # We simulate "boto3 missing" by monkeypatching Boto3ClientFactory to
        # raise ModuleNotFoundError, without needing boto3 absent for real.
        import src.discovery as discovery_module

        original = discovery_module.Boto3ClientFactory

        class RaisingFactory:
            def __init__(self) -> None:
                raise ModuleNotFoundError("boto3")

        discovery_module.Boto3ClientFactory = RaisingFactory  # type: ignore[misc]
        try:
            scope = Scope(access_mode="minimum_read_only")
            facts, evidence, observations = run_aws_discovery(scope, client_factory=None)
        finally:
            discovery_module.Boto3ClientFactory = original  # type: ignore[misc]

        self.assertEqual(1, len(evidence))
        self.assertEqual("unknown", evidence[0].status)
        self.assertEqual((), observations)
        self.assertFalse(facts["signals"]["aws_discovery"]["detected"])


if __name__ == "__main__":
    unittest.main()



class TagDiscoveryTests(unittest.TestCase):
    """Cost-tag discovery must describe its bounded evidence honestly."""

    def test_tag_key_pagination_and_resource_sample_detect_grouping_signal(self):
        def tag_keys(**kwargs: Any) -> dict[str, Any]:
            if kwargs.get("PaginationToken") == "page-2":
                return {"TagKeys": ["Customer"]}
            return {"TagKeys": ["Environment"], "PaginationToken": "page-2"}

        def tagged_resources(**kwargs: Any) -> dict[str, Any]:
            self.assertEqual(100, kwargs["ResourcesPerPage"])
            return {
                "ResourceTagMappingList": [
                    {"ResourceARN": "arn:aws:lambda:us-east-1:123456789012:function:test", "Tags": [{"Key": "Tenant", "Value": "demo"}]}
                ]
            }

        factory = _minimal_factory(
            {
                "resourcegroupstaggingapi": {
                    "get_tag_keys": tag_keys,
                    "get_resources": tagged_resources,
                }
            }
        )
        facts, _evidence, observations = run_aws_discovery(
            Scope(access_mode="minimum_read_only"), client_factory=factory
        )

        signal = facts["signals"]["cost_allocation_tags"]
        self.assertTrue(signal["detected"])
        self.assertFalse(signal["confirmed"])
        self.assertIn("customer", signal["matched_tag_keys"])
        self.assertEqual(1, signal["tagged_resource_sample_count"])
        self.assertTrue(any("bounded tagged-resource sample" in item for item in observations))

    def test_absent_matching_tag_key_is_unknown_not_missing_cost_allocation(self):
        factory = _minimal_factory()
        facts, _evidence, observations = run_aws_discovery(
            Scope(access_mode="minimum_read_only"), client_factory=factory
        )
        result = assess_payload({"facts": facts})
        cam01 = next(
            control
            for dimension in result.dimensions
            for control in dimension.controls
            if control.id == "CAM-01"
        )

        self.assertEqual("unknown", cam01.status)
        self.assertIn("cost allocation remains unverified", cam01.evidence_summary)
        self.assertTrue(any("does not prove" in item for item in observations))

    def test_minimum_actions_include_both_tagging_api_permissions(self):
        self.assertIn("tag:GetResources", MINIMUM_READ_ONLY_ACTIONS)
        self.assertIn("tag:GetTagKeys", MINIMUM_READ_ONLY_ACTIONS)



class TagSignalFilteringTests(unittest.TestCase):
    def test_aws_managed_product_tag_is_not_customer_cost_allocation_evidence(self):
        factory = _minimal_factory(
            {
                "resourcegroupstaggingapi": {
                    "get_tag_keys": {
                        "TagKeys": ["aws:servicecatalog:productarn"]
                    },
                    "get_resources": {
                        "ResourceTagMappingList": [
                            {
                                "ResourceARN": "arn:aws:s3:::example",
                                "Tags": [
                                    {
                                        "Key": "aws:servicecatalog:productarn",
                                        "Value": "example",
                                    }
                                ],
                            }
                        ]
                    },
                }
            }
        )
        facts, _evidence, _observations = run_aws_discovery(
            Scope(access_mode="minimum_read_only"), client_factory=factory
        )

        signal = facts["signals"]["cost_allocation_tags"]
        self.assertFalse(signal["detected"])
        self.assertEqual([], signal["matched_tag_keys"])


class DiscoveryFailureLoggingTests(unittest.TestCase):
    def test_failed_call_logs_service_action_and_error_code(self):
        import io
        import json

        from src.discovery import _call
        from src.observability import configure_logging

        class DenyingClient:
            def list_functions(self, **kwargs: Any) -> Any:
                raise FakeClientError("AccessDeniedException")

        class Factory:
            def client(self, service_name: str) -> Any:
                return DenyingClient()

        stream = io.StringIO()
        configure_logging("INFO", stream=stream)
        try:
            result, evidence, denied = _call(Factory(), "lambda", "list_functions", ("TAI-01",))
        finally:
            configure_logging("INFO")

        self.assertIsNone(result)
        self.assertIsNotNone(evidence)
        (record,) = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual("aws_discovery_call_failed", record["event"])
        self.assertEqual("WARNING", record["level"])
        self.assertEqual("lambda", record["service"])
        self.assertEqual("lambda:listfunctions", record["action"].lower())
        self.assertEqual("AccessDeniedException", record["error_code"])
        self.assertTrue(record["permission_denied"])


class Boto3ClientRetryConfigTests(unittest.TestCase):
    """Real clients must retry transient throttling/network errors.

    boto3 and botocore are stubbed through sys.modules so this test keeps the
    module's rule of never importing the real AWS SDK.
    """

    def _build_factory(self, limits: Any = None) -> tuple[Any, list[dict[str, Any]]]:
        import sys
        import types
        from unittest import mock

        from src.discovery import Boto3ClientFactory

        calls: list[dict[str, Any]] = []
        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = lambda service_name, config=None: calls.append(  # type: ignore[attr-defined]
            {"service": service_name, "config": config}
        )
        fake_config_module = types.ModuleType("botocore.config")
        fake_config_module.Config = lambda **kwargs: kwargs  # type: ignore[attr-defined]
        modules = {
            "boto3": fake_boto3,
            "botocore": types.ModuleType("botocore"),
            "botocore.config": fake_config_module,
        }
        with mock.patch.dict(sys.modules, modules):
            factory = Boto3ClientFactory(limits)
        return factory, calls

    def test_clients_use_configured_retry_settings(self):
        from src.config import RuntimeLimits

        factory, calls = self._build_factory(
            RuntimeLimits(aws_max_attempts=7, aws_retry_mode="standard")
        )
        factory.client("ec2")

        self.assertEqual("ec2", calls[0]["service"])
        self.assertEqual(
            {"retries": {"max_attempts": 7, "mode": "standard"}}, calls[0]["config"]
        )

    def test_default_retry_mode_is_adaptive(self):
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AWS_DISCOVERY_RETRY_MODE", None)
            os.environ.pop("AWS_DISCOVERY_MAX_ATTEMPTS", None)
            factory, calls = self._build_factory()
        factory.client("lambda")

        self.assertEqual("adaptive", calls[0]["config"]["retries"]["mode"])
        self.assertEqual(5, calls[0]["config"]["retries"]["max_attempts"])
