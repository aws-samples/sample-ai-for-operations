# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Shared pytest fixtures.

Isolates the file/memory cache between tests so a cached value from one test
never satisfies a mocked call in another (which would skip the code path under
test and understate coverage).
"""

import shutil

import pytest

import cache
import config


@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path, monkeypatch):
    # Point the /tmp cache tier at a per-test directory and clear memory.
    test_cache_dir = str(tmp_path / "byoc-cache")
    monkeypatch.setattr(config, "CACHE_TMP_DIR", test_cache_dir)
    monkeypatch.setattr(cache, "CACHE_TMP_DIR", test_cache_dir)
    cache.clear()
    yield
    cache.clear()
    shutil.rmtree(test_cache_dir, ignore_errors=True)
