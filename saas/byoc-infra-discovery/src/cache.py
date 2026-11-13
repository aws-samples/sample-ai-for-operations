# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""In-memory + /tmp TTL cache for resolved infrastructure facts.

Deliberately NO durable/paid store (no Amazon DynamoDB). Cost decision:
the account-independent primary sources (SSM global-infrastructure, the AWS
Price List API) are free to call, so a cache miss costs latency, not dollars.

Two tiers within a single Lambda execution environment:
  1. process-memory dict  -- fastest, survives warm re-invocations
  2. /tmp JSON files      -- survives handler re-entry in the same warm env

The cache is intentionally cold on new / scaled-out environments.
"""

import hashlib
import json
import os
import time
from typing import Any, Callable, Optional

from config import CACHE_TMP_DIR, CACHE_TTL_SECONDS
from logging_util import log_event

# process-memory tier: key -> (expires_at_epoch, value)
_MEMORY: dict[str, tuple[float, Any]] = {}


def _make_key(dataset: str, region: Optional[str], params: Optional[dict]) -> str:
    raw = json.dumps(
        {"dataset": dataset, "region": region, "params": params or {}},
        sort_keys=True,
        default=str,
    )
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    return f"{dataset}__{region or 'global'}__{digest}"


def _tmp_path(key: str) -> str:
    return os.path.join(CACHE_TMP_DIR, f"{key}.json")


def _read_tmp(key: str) -> Optional[tuple[float, Any]]:
    path = _tmp_path(key)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        return float(payload["expires_at"]), payload["value"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_tmp(key: str, expires_at: float, value: Any) -> None:
    try:
        os.makedirs(CACHE_TMP_DIR, exist_ok=True)
        with open(_tmp_path(key), "w", encoding="utf-8") as fh:
            json.dump({"expires_at": expires_at, "value": value}, fh, default=str)
    except OSError:
        # /tmp write failure is non-fatal; memory tier still works.
        pass


def get_or_compute(
    dataset: str,
    compute: Callable[[], Any],
    region: Optional[str] = None,
    params: Optional[dict] = None,
    ttl_seconds: Optional[int] = None,
) -> Any:
    """Return a cached value or compute, cache, and return it.

    Args:
        dataset: logical dataset name (e.g. "regions", "availability_zones").
        compute: zero-arg callable that produces the value on a cache miss.
        region: optional region scoping the cache key.
        params: optional extra params that vary the result.
        ttl_seconds: override the default TTL for this entry.
    """
    ttl = CACHE_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    key = _make_key(dataset, region, params)
    now = time.time()

    # tier 1: memory
    entry = _MEMORY.get(key)
    if entry and entry[0] > now:
        log_event("cache_hit", tier="memory", dataset=dataset, region=region)
        return entry[1]

    # tier 2: /tmp
    tmp_entry = _read_tmp(key)
    if tmp_entry and tmp_entry[0] > now:
        _MEMORY[key] = tmp_entry
        log_event("cache_hit", tier="tmp", dataset=dataset, region=region)
        return tmp_entry[1]

    # miss
    log_event("cache_miss", dataset=dataset, region=region)
    value = compute()
    expires_at = now + ttl
    _MEMORY[key] = (expires_at, value)
    _write_tmp(key, expires_at, value)
    return value


def clear() -> None:
    """Clear the in-memory tier (used by tests)."""
    _MEMORY.clear()
