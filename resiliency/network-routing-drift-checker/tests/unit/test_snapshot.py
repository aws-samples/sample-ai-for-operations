# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Snapshot helpers."""

from drift_core.snapshot import ip_family, tag_value, tags_to_dict


def test_tags_to_dict():
    assert tags_to_dict([{"Key": "Environment", "Value": "prod"}, {"Key": "x"}, {"Value": "orphan"}]) == {
        "Environment": "prod", "x": ""}
    assert tags_to_dict(None) == {}
    assert tags_to_dict([{"key": "a", "value": "b"}], "key", "value") == {"a": "b"}


def test_tag_value_case_insensitive_key_and_trim():
    assert tag_value({"environment ": " prod "}, "Environment") == "prod"
    assert tag_value({"Environment": "  "}, "Environment") is None
    assert tag_value({}, "Environment") is None


def test_ip_family():
    assert ip_family("10.0.0.0/8") == "ipv4" and ip_family("2001:db8::/32") == "ipv6"
