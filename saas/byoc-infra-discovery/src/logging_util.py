# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Structured JSON logging for the byoc-infra-discovery agent.

Every log line is a single JSON object so CloudWatch Logs Insights can query
by field (source, region, cache_hit, duration_ms). No full model prompts or
responses are logged.
"""

import json
import logging
import sys

from config import LOG_LEVEL

_LOGGER_NAME = "byoc-infra-discovery"


def _build_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(LOG_LEVEL)
    logger.propagate = False
    return logger


_logger = _build_logger()


def log_event(event: str, **fields) -> None:
    """Emit a structured JSON log line.

    Args:
        event: short event name, e.g. "resolve_regions", "cache_hit".
        **fields: additional structured fields (region, source, duration_ms...).
    """
    record = {"event": event}
    record.update(fields)
    try:
        _logger.info(json.dumps(record, default=str))
    except (TypeError, ValueError):
        # Never let logging crash the handler.
        _logger.info(json.dumps({"event": event, "log_error": "unserializable_fields"}))
