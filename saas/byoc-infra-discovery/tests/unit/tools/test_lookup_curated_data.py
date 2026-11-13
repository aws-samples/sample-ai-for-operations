# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from tools.lookup_curated_data import lookup_curated_data_impl


def test_eks_ecr_registry_lookup():
    r = lookup_curated_data_impl("eks_ecr_registries", "eu-south-2")
    assert r["found"] is True
    assert r["value"] == "455263428931"
    assert r["source"] == "curated"
    assert r["source_url"]
    assert r["last_updated"]


def test_s3_us_east_1_is_null():
    r = lookup_curated_data_impl("s3_location_constraints", "us-east-1")
    assert r["found"] is True
    assert r["value"] is None


def test_eks_eol_lookup():
    r = lookup_curated_data_impl("eks_eol_dates", "1.30")
    assert r["found"] is True
    assert r["value"] == "2025-07-23"


def test_eni_max_pods_lookup():
    r = lookup_curated_data_impl("eni_max_pods", "m6i.large")
    assert r["found"] is True
    assert r["value"] == 29


def test_whole_dataset_when_no_key():
    r = lookup_curated_data_impl("eks_ecr_registries")
    assert isinstance(r["value"], dict)
    assert "eu-south-2" in r["value"]


def test_missing_key_returns_not_found():
    r = lookup_curated_data_impl("eks_ecr_registries", "xx-fake-1")
    assert r["found"] is False
    assert r["value"] is None


def test_invalid_dataset():
    r = lookup_curated_data_impl("bogus")
    assert r["error"] is True
    assert r["error_type"] == "invalid_dataset"
