# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from tools.format_response import (
    format_error_response_impl,
    format_fact_response_impl,
    format_readiness_response_impl,
    format_response,
)


def test_fact_response_shape():
    r = format_fact_response_impl(
        "availability_zones",
        {"azs": [{"az_id": "apse7-az1"}], "az_names_available": False},
        source="ssm-global-infrastructure",
        confidence="high",
        region="ap-southeast-7",
    )
    assert r["query_mode"] == "fact"
    assert r["dataset"] == "availability_zones"
    assert r["region"] == "ap-southeast-7"
    assert r["source"] == "ssm-global-infrastructure"
    assert r["result"]["az_names_available"] is False


def test_fact_response_optional_fields_omitted():
    r = format_fact_response_impl("regions", {"regions": []})
    assert "region" not in r
    assert "source" not in r
    assert "confidence" not in r


def test_readiness_response_shape():
    r = format_readiness_response_impl(
        "eu-south-2",
        "blocked",
        [{"code": "no-ami-published", "reason": "no AMI"}],
        {"ami": {"ami_available": False}},
        "medium",
        target={"instance_type": "m6i.large"},
    )
    assert r["query_mode"] == "readiness"
    assert r["verdict"] == "blocked"
    assert r["target"]["instance_type"] == "m6i.large"


def test_readiness_response_without_target():
    r = format_readiness_response_impl("us-east-1", "ready", [], {}, "high")
    assert "target" not in r


def test_error_response_shape():
    r = format_error_response_impl("invalid_region", "Region 'xx-fake-1' not found.")
    assert r["error"] is True
    assert r["error_type"] == "invalid_region"


def test_format_response_dispatch_fact():
    r = format_response("fact", {"dataset": "regions", "result": {"regions": []}})
    assert r["query_mode"] == "fact"


def test_format_response_dispatch_readiness():
    r = format_response(
        "readiness",
        {
            "region": "us-east-1",
            "verdict": "ready",
            "blockers": [],
            "facts": {},
            "confidence": "high",
        },
    )
    assert r["query_mode"] == "readiness"


def test_format_response_dispatch_error():
    r = format_response("error", {"error_type": "bad", "message": "m"})
    assert r["error_type"] == "bad"


def test_format_response_invalid_mode():
    r = format_response("bogus", {})
    assert r["error_type"] == "invalid_mode"
