# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Integration test: the readiness-investigation flow for a non-enabled region.

Exercises the precision pipeline end-to-end (resolver outputs -> compute
deployability -> format response) for the documented eu-south-2 "no AMI ->
blocked" case, without invoking Amazon Bedrock or live AWS.
"""

from tools.compute_deployability import compute_deployability_impl
from tools.count_azs import count_azs_impl
from tools.format_response import format_readiness_response_impl


def test_non_enabled_region_no_ami_is_blocked():
    # Simulated resolver outputs for an opt-in region with no published AMI.
    azs = [{"az_id": "eus2-az1"}, {"az_id": "eus2-az2"}, {"az_id": "eus2-az3"}]
    az_count = count_azs_impl(azs)["count"]

    facts_bundle = {
        "region_exists": True,
        "ec2_available": True,
        "eks_required": True,
        "eks_available": True,
        "ami_available": False,  # no Ubuntu 24.04 AMI published
        "eks_ecr_registry_present": True,
        "az_count": az_count,
        "instance_type_required": True,
        "instance_type_offered": True,
        "source_confidences": ["high", "high", "medium"],
    }

    verdict = compute_deployability_impl(facts_bundle)
    assert verdict["verdict"] == "blocked"
    assert any(b["code"] == "no-ami-published" for b in verdict["blockers"])
    assert verdict["confidence"] == "medium"

    response = format_readiness_response_impl(
        region="eu-south-2",
        verdict=verdict["verdict"],
        blockers=verdict["blockers"],
        facts={
            "availability_zones": {
                "azs": azs,
                "az_names_available": False,
                "source": "ssm-global-infrastructure",
            },
            "ami": {"ami_available": False, "source": "ec2-live"},
        },
        confidence=verdict["confidence"],
        target={"instance_type": "m6i.large", "eks_version": "1.30"},
    )

    # Valid, parseable structured JSON contract, no exception.
    assert response["query_mode"] == "readiness"
    assert response["region"] == "eu-south-2"
    assert response["verdict"] == "blocked"
    assert response["facts"]["availability_zones"]["az_names_available"] is False


def test_fully_enabled_region_is_ready():
    facts_bundle = {
        "region_exists": True,
        "ec2_available": True,
        "eks_required": True,
        "eks_available": True,
        "ami_available": True,
        "eks_ecr_registry_present": True,
        "az_count": 6,
        "instance_type_required": True,
        "instance_type_offered": True,
        "source_confidences": ["high"],
    }
    verdict = compute_deployability_impl(facts_bundle)
    assert verdict["verdict"] == "ready"
    assert verdict["blockers"] == []
