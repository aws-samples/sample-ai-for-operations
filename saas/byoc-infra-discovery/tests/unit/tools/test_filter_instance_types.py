# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
import pytest

from tools.filter_instance_types import filter_instance_types_impl

TYPES = [
    {"name": "m6i.large", "vcpu": 2, "memory_mib": 8192, "arch": "x86_64"},
    {"name": "m6g.large", "vcpu": 2, "memory_mib": 8192, "arch": "arm64"},
    {"name": "c6i.2xlarge", "vcpu": 8, "memory_mib": 16384, "arch": "x86_64"},
    {"name": "unknown", "vcpu": None, "memory_mib": None, "arch": None},
]


def test_no_filters_returns_all():
    r = filter_instance_types_impl(TYPES)
    assert r["match_count"] == 4


def test_min_vcpu():
    r = filter_instance_types_impl(TYPES, min_vcpu=8)
    assert r["match_count"] == 1
    assert r["matches"][0]["name"] == "c6i.2xlarge"


def test_min_memory_excludes_unknown():
    r = filter_instance_types_impl(TYPES, min_memory_mib=8192)
    assert r["match_count"] == 3  # unknown (None) excluded


def test_arch_filter_case_insensitive():
    r = filter_instance_types_impl(TYPES, arch="ARM64")
    assert r["match_count"] == 1
    assert r["matches"][0]["name"] == "m6g.large"


def test_combined_filters():
    r = filter_instance_types_impl(TYPES, min_vcpu=2, arch="x86_64")
    assert {m["name"] for m in r["matches"]} == {"m6i.large", "c6i.2xlarge"}


@pytest.mark.parametrize("bad", ["str", 123, None])
def test_invalid_input(bad):
    r = filter_instance_types_impl(bad)
    assert r["error_type"] == "invalid_input"
