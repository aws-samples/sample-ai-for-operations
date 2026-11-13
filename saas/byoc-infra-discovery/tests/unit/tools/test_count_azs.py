# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from tools.count_azs import count_azs_impl


def test_counts_az_dicts():
    assert count_azs_impl([{"az_id": "a"}, {"az_id": "b"}]) == {"count": 2}


def test_counts_strings():
    assert count_azs_impl(["a", "b", "c"]) == {"count": 3}


def test_dedupes():
    assert count_azs_impl([{"az_id": "a"}, {"az_id": "a"}, "a"]) == {"count": 1}


def test_empty_list():
    assert count_azs_impl([]) == {"count": 0}


def test_ignores_malformed_entries():
    assert count_azs_impl([{"no_id": "x"}, {"az_id": "a"}, "", 5]) == {"count": 1}


def test_invalid_input():
    result = count_azs_impl("not-a-list")
    assert result["error"] is True
    assert result["error_type"] == "invalid_input"
