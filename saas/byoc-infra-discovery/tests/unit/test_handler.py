# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from unittest.mock import patch

import pytest

import handler
from schemas import AvailabilityZone, GatheredFacts


def test_extract_query_direct():
    assert handler._extract_query({"query": "  AMIs for eu-south-2 "}) == "AMIs for eu-south-2"


def test_extract_query_api_gateway_body():
    assert handler._extract_query({"body": '{"query": "hi"}'}) == "hi"


def test_extract_query_missing():
    with pytest.raises(ValueError):
        handler._extract_query({"foo": "bar"})


def test_extract_query_bad_body_json():
    with pytest.raises(ValueError):
        handler._extract_query({"body": "{not json"})


def test_handler_bad_request_short_circuits():
    r = handler.handler({"foo": "bar"})
    assert r["error"] is True
    assert r["error_type"] == "bad_request"


@patch("handler.gather_facts")
def test_handler_internal_error_is_structured(mock_gather):
    mock_gather.side_effect = RuntimeError("boom")
    r = handler.handler({"query": "AMIs for eu-south-2"})
    assert r["error"] is True
    assert r["error_type"] == "internal_error"
    assert "boom" not in r["message"]


@patch("handler.gather_facts")
def test_handler_readiness_verdict_decided_in_code(mock_gather):
    # The model gathers facts; the handler must compute verdict + confidence.
    # Even if the gathered facts could tempt a "ready", the no-AMI fact blocks.
    mock_gather.return_value = GatheredFacts(
        query_mode="readiness",
        region="eu-south-2",
        region_long_name="Europe (Spain)",
        instance_type="m6i.large",
        eks_required=True,
        region_exists=True,
        ec2_available=True,
        eks_available=True,
        availability_zones=[
            AvailabilityZone(az_id="eus2-az1"),
            AvailabilityZone(az_id="eus2-az2"),
            AvailabilityZone(az_id="eus2-az3"),
        ],
        az_names_available=False,
        ami_available=False,
        instance_type_offered=False,
        instance_type_offered_source="pricing-api",
        eks_ecr_registry="455263428931",
        source_confidences=["high", "high"],
    )
    r = handler.handler({"query": "Is eu-south-2 ready for EKS on m6i.large?"})
    assert r["query_mode"] == "readiness"
    assert r["verdict"] == "blocked"
    codes = {b["code"] for b in r["blockers"]}
    assert "no-ami-published" in codes
    assert "instance-type-not-offered" in codes
    # Pricing-only "not offered" caps confidence at medium — decided in code.
    assert r["confidence"] == "medium"
    assert r["facts"]["availability_zones"]["az_names_available"] is False


@patch("handler.gather_facts")
def test_handler_ready_verdict(mock_gather):
    mock_gather.return_value = GatheredFacts(
        query_mode="readiness",
        region="us-east-1",
        eks_required=True,
        region_exists=True,
        ec2_available=True,
        eks_available=True,
        availability_zones=[AvailabilityZone(az_id=f"use1-az{i}") for i in range(1, 7)],
        ami_available=True,
        instance_type="m6i.large",
        instance_type_offered=True,
        instance_type_offered_source="ec2-live",
        eks_ecr_registry="602401143452",
        source_confidences=["high"],
    )
    r = handler.handler({"query": "Is us-east-1 ready?"})
    assert r["verdict"] == "ready"
    assert r["blockers"] == []


@patch("handler.gather_facts")
def test_handler_incomplete_facts_does_not_fabricate_verdict(mock_gather):
    # Gathering failed: core facts are None and no AZs. Must NOT emit a verdict
    # built from empty data (the regression that produced spurious blockers).
    mock_gather.return_value = GatheredFacts(
        query_mode="readiness",
        region="eu-south-2",
        instance_type="m6i.large",
        eks_required=True,
        region_exists=None,
        ec2_available=None,
        ami_available=None,
        availability_zones=[],
    )
    r = handler.handler({"query": "Is eu-south-2 ready?"})
    assert r["error"] is True
    assert r["error_type"] == "incomplete_facts"
    assert "verdict" not in r


@patch("handler.gather_facts")
def test_handler_fact_mode(mock_gather):
    mock_gather.return_value = GatheredFacts(
        query_mode="fact",
        region="ap-southeast-7",
        fact_dataset="availability_zones",
        fact_source="ssm-global-infrastructure",
        fact_confidence="high",
        availability_zones=[
            AvailabilityZone(az_id="apse7-az1"),
            AvailabilityZone(az_id="apse7-az2"),
        ],
        az_names_available=False,
    )
    r = handler.handler({"query": "AZs for ap-southeast-7"})
    assert r["query_mode"] == "fact"
    assert r["dataset"] == "availability_zones"
    assert r["result"]["az_names_available"] is False
    assert len(r["result"]["azs"]) == 2
