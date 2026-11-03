# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Fixture sanitizer: consistent mapping, no double replacement, no leaks."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))

from sanitize import Sanitizer, leaks  # noqa: E402

ACCT = "987654321098"
UUID = "5f8e2a1c-3b4d-4e6f-8a9b-0c1d2e3f4a5b"


def test_accounts_ids_uuids_mapped_consistently():
    s = Sanitizer()
    out = s({
        "OwnerId": ACCT,
        "Arn": f"arn:aws:ec2:eu-central-1:{ACCT}:transit-gateway/tgw-0a1b2c3d4e5f60718",
        "TransitGatewayId": "tgw-0a1b2c3d4e5f60718",
        "routes": {"tgw-rtb-0fedcba9876543210": [{"ResourceId": "vpc-0123456789abcdef0"}]},
        "directConnectGatewayId": UUID,
        "assoc": f"{UUID}",
    })
    assert out["OwnerId"] == "123456789012"
    assert out["TransitGatewayId"] == "tgw-00000000000000001"
    assert out["Arn"] == "arn:aws:ec2:eu-central-1:123456789012:transit-gateway/tgw-00000000000000001"
    assert list(out["routes"]) == ["tgw-rtb-00000000000000001"]
    assert out["directConnectGatewayId"] == out["assoc"] == "00000001-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert leaks(out, {ACCT, UUID, *s.ids}) == []


def test_uuid_placeholder_not_reprocessed_as_account():
    s = Sanitizer()
    s({"a": UUID, "b": "11111111-2222-4333-8444-555555555555"})
    assert s.accounts == {}


def test_ips_private_kept_public_replaced_and_secrets_blanked():
    s = Sanitizer()
    out = s({"amazonAddress": "169.254.10.1/30", "peer": "203.0.113.77", "cidr": "10.1.0.0/16",
             "authKey": "super-secret", "Tags": [{"Key": "Owner", "Value": "jane@example.org"}]})
    assert out["amazonAddress"] == "169.254.10.1/30" and out["cidr"] == "10.1.0.0/16"
    assert out["peer"].startswith("198.51.100.")
    assert out["authKey"] == ""
    assert out["Tags"][0]["Value"] == "user@example.com"


def test_placeholder_accounts_and_twelve_digit_ints():
    s = Sanitizer()
    out = s({"a": "123456789012", "n": int(ACCT), "flag": True})
    assert out == {"a": "123456789012", "n": 123456789012, "flag": True}


def test_leaks_detects_survivor():
    assert leaks({"x": f"prefix-{ACCT}"}, {ACCT}) == [ACCT]
