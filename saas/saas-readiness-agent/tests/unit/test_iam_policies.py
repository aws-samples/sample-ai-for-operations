# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""The published IAM policies must match the code and stay read-only."""

import ast
import json
import unittest
from pathlib import Path

from src.discovery import (
    ENHANCED_READ_ONLY_ACTIONS,
    MINIMUM_READ_ONLY_ACTIONS,
    PERMISSION_CONTROL_MAP,
)
from src.iam_policies import POLICY_DIR, POLICY_FILES, READ_ONLY_PREFIXES, render

# boto3 client name / method -> IAM action, where the IAM name differs from
# the SDK name. Everything else is service:PascalCaseMethod.
SDK_TO_IAM = {
    ("bedrock-agentcore-control", "list_agent_runtimes"): "bedrock-agentcore:ListAgentRuntimes",
    ("bedrock-agentcore-control", "list_gateways"): "bedrock-agentcore:ListGateways",
    ("rds", "describe_db_instances"): "rds:DescribeDBInstances",
    ("resourcegroupstaggingapi", "get_resources"): "tag:GetResources",
    ("resourcegroupstaggingapi", "get_tag_keys"): "tag:GetTagKeys",
    ("s3", "list_buckets"): "s3:ListAllMyBuckets",
    ("wafv2", "list_web_acls"): "wafv2:ListWebACLs",
}


def _discovery_calls():
    tree = ast.parse(Path("src/discovery.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_call":
            service, method = node.args[1].value, node.args[2].value
            yield SDK_TO_IAM.get(
                (service, method),
                service + ":" + "".join(part.capitalize() for part in method.split("_")),
            )


class PublishedPolicyTests(unittest.TestCase):
    def test_policy_files_match_the_code(self):
        for name, actions in POLICY_FILES.items():
            with self.subTest(policy=name):
                published = (POLICY_DIR / name).read_text(encoding="utf-8")
                self.assertEqual(
                    render(actions), published, "Run: python -m src.iam_policies --write"
                )

    def test_policies_are_read_only(self):
        for name in POLICY_FILES:
            policy = json.loads((POLICY_DIR / name).read_text(encoding="utf-8"))
            for statement in policy["Statement"]:
                self.assertEqual("Allow", statement["Effect"])
                for action in statement["Action"]:
                    verb = action.split(":", 1)[1]
                    with self.subTest(action=action):
                        self.assertTrue(verb.startswith(READ_ONLY_PREFIXES), action)

    def test_every_discovery_call_is_in_the_minimum_or_enhanced_policy(self):
        declared = set(ENHANCED_READ_ONLY_ACTIONS)
        missing = sorted(set(_discovery_calls()) - declared)
        self.assertEqual([], missing)

    def test_minimum_is_a_subset_of_enhanced(self):
        self.assertTrue(set(MINIMUM_READ_ONLY_ACTIONS) <= set(ENHANCED_READ_ONLY_ACTIONS))

    def test_every_declared_action_maps_to_controls(self):
        unmapped = sorted(set(ENHANCED_READ_ONLY_ACTIONS) - set(PERMISSION_CONTROL_MAP))
        self.assertEqual([], unmapped)


if __name__ == "__main__":
    unittest.main()
