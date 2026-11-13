# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Directly exercise the live-call helper branches (mocked EC2 clients)."""

from unittest.mock import MagicMock, patch

from tools.resolve_amis import _live_images, _ssm_public_ami
from tools.resolve_availability_zones import _fetch_live_names
from tools.resolve_instance_types import _live_enrich


@patch("tools.resolve_instance_types.ec2_client")
def test_live_enrich_maps_ec2_attributes(mock_ec2):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "InstanceTypes": [
                {
                    "InstanceType": "m6i.large",
                    "VCpuInfo": {"DefaultVCpus": 2},
                    "MemoryInfo": {"SizeInMiB": 8192},
                    "ProcessorInfo": {"SupportedArchitectures": ["x86_64"]},
                    "InstanceStorageSupported": False,
                }
            ]
        }
    ]
    client.get_paginator.return_value = paginator
    mock_ec2.return_value = client

    out = _live_enrich("us-east-1", None)
    assert out[0]["name"] == "m6i.large"
    assert out[0]["arch"] == "x86_64"
    assert out[0]["source"] == "ec2-live"
    assert out[0]["confidence"] == "high"


@patch("tools.resolve_availability_zones.ec2_client")
def test_fetch_live_names_builds_id_to_name_map(mock_ec2):
    client = MagicMock()
    client.describe_availability_zones.return_value = {
        "AvailabilityZones": [
            {"ZoneId": "use1-az1", "ZoneName": "us-east-1a"},
            {"ZoneId": "use1-az2", "ZoneName": "us-east-1b"},
        ]
    }
    mock_ec2.return_value = client
    names = _fetch_live_names("us-east-1")
    assert names == {"use1-az1": "us-east-1a", "use1-az2": "us-east-1b"}


@patch("tools.resolve_amis.ec2_client")
def test_live_images_sorted_newest_first(mock_ec2):
    client = MagicMock()
    client.describe_images.return_value = {
        "Images": [
            {"ImageId": "ami-old", "Name": "old", "CreationDate": "2025-01-01"},
            {"ImageId": "ami-new", "Name": "new", "CreationDate": "2026-01-01"},
        ]
    }
    mock_ec2.return_value = client
    images = _live_images("us-east-1", "ubuntu-*", "099720109477")
    assert images[0]["id"] == "ami-new"


@patch("tools.resolve_amis.ssm_regional_client")
def test_ssm_public_ami_returns_value(mock_ssm):
    client = MagicMock()
    client.get_parameter.return_value = {"Parameter": {"Value": "ami-0ssm"}}
    mock_ssm.return_value = client
    out = _ssm_public_ami("us-east-1", "/aws/service/canonical/...")
    assert out["id"] == "ami-0ssm"
