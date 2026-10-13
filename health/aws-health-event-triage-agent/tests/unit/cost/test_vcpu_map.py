# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.cost.vcpu_map.map_instance_class_to_vcpu."""

from __future__ import annotations

import json
import os

import pytest

import src.cost.vcpu_map as vcpu_mod
from src.cost.vcpu_map import map_instance_class_to_vcpu


@pytest.fixture(autouse=True)
def _reset_cache():
    vcpu_mod._vcpu_cache = None
    yield
    vcpu_mod._vcpu_cache = None


class TestKnownInstanceClasses:
    def test_known_class_returns_vcpu_count(self, tmp_path):
        path = tmp_path / "vcpu.json"
        path.write_text(json.dumps({"db.r5.large": 2, "db.r5.xlarge": 4}))
        os.environ["VCPU_MAP_PATH"] = str(path)
        try:
            assert map_instance_class_to_vcpu("db.r5.large") == 2
            assert map_instance_class_to_vcpu("db.r5.xlarge") == 4
        finally:
            del os.environ["VCPU_MAP_PATH"]


class TestUnknownInstanceClass:
    def test_unknown_class_returns_none(self, tmp_path):
        path = tmp_path / "vcpu.json"
        path.write_text(json.dumps({"db.r5.large": 2}))
        os.environ["VCPU_MAP_PATH"] = str(path)
        try:
            assert map_instance_class_to_vcpu("db.exotic.99xlarge") is None
        finally:
            del os.environ["VCPU_MAP_PATH"]

    def test_missing_file_returns_none_for_any_class(self, tmp_path):
        os.environ["VCPU_MAP_PATH"] = str(tmp_path / "nonexistent.json")
        try:
            assert map_instance_class_to_vcpu("db.r5.large") is None
        finally:
            del os.environ["VCPU_MAP_PATH"]
