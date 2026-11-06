# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: walk ``AWSLogs/`` in the configured flow-log bucket (this bucket only)."""

from __future__ import annotations

import logging
from typing import Any

from ..core import s3layout

logger = logging.getLogger(__name__)


def list_log_prefixes(
    s3: Any, bucket: str, first_day: str, last_day: str, prefix: str = "AWSLogs/"
) -> s3layout.LogInventory:
    """Accounts, Regions, days and object bytes present under the bucket for the window."""
    try:
        return s3layout.walk(s3, bucket, first_day, last_day, prefix)
    except Exception as exc:
        logger.error(  # logs the context for the operator, then re-raises to the caller  # nosemgrep: logging-error-without-handling
            '{"event": "list_log_prefixes_failed", "bucket": "%s", "error": "%s"}', bucket, str(exc)[:200]
        )
        raise
