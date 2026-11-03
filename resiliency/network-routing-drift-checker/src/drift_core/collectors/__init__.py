# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data-retrieval collectors (read-only Describe/Get/List/Search calls only).

Each collector is split in two so recorded responses can be replayed in tests:
- fetch_*(client, ...) -> raw dict of API responses (the only code that does I/O)
- normalize_*(raw, ...) -> snapshot dict (pure; shape documented in drift_core.snapshot)
"""

from __future__ import annotations

from typing import Any

from botocore.config import Config

# Adaptive client-side rate limiting plus retries for throttling (tasks.md 1.15).
#
# max_attempts is deliberately low (3, not botocore's higher defaults) because the Step Functions
# state machine (infra/lib/drift-checker-stack.ts) retries the WHOLE collect-region/collect-cloudwan
# Lambda invocation on CollectionThrottled -- up to 5 times for a Region, 3 for Cloud WAN -- and each
# retry re-invokes the Lambda fresh and re-paginates every Describe/Search call from the start.
# Retrying at both layers multiplies calls (pre-release review finding, 2026-10-18): with the old
# max_attempts=8, a persistently-throttled Region could reach roughly 8 x 6 = 48 attempts per call
# before the state machine's own Catch gave up and marked the Region "not evaluated". With
# max_attempts=3, the same worst case is 3 x 6 = 18 attempts per call -- the state machine retry is
# kept because it's visible in execution history and already drives the per-Region fallback; the
# botocore layer only needs to smooth over the few seconds of a single invocation.
CLIENT_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 3},
    connect_timeout=5,
    read_timeout=30,
    user_agent_extra="network-routing-drift-checker",
)


def paginate(client: Any, operation: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Collect every item of `result_key` across all pages of a paginated operation."""
    items: list[dict[str, Any]] = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(result_key) or [])
    return items
