# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Structured JSON logging for the agent runtime and AWS discovery.

Each record is one JSON object per line on stderr, which Amazon Bedrock
AgentCore Runtime forwards to Amazon CloudWatch Logs. Callers pass only
operational fields (event names, identifiers, durations, AWS error codes).
Prompts, model responses, and customer answers are never logged.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_ROOT_LOGGER_NAME = "saas_readiness"
_RESERVED = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}

# Library default: silent until an entrypoint calls configure_logging(), so
# the local REPL and CLI output are unchanged.
logging.getLogger(_ROOT_LOGGER_NAME).addHandler(logging.NullHandler())


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                entry[key] = value
        if record.exc_info and record.exc_info[0] is not None:
            # Exception type only: messages can echo request content.
            entry["exception_type"] = record.exc_info[0].__name__
        return json.dumps(entry, default=str, sort_keys=True)


def get_logger(name: str) -> logging.Logger:
    """Return a child of the project logger so one handler covers all modules."""
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")


def configure_logging(level: str = "INFO", stream: Any = None) -> logging.Logger:
    """Attach a single JSON handler to the project logger. Safe to call repeatedly."""
    root = logging.getLogger(_ROOT_LOGGER_NAME)
    root.setLevel(level)
    root.propagate = False
    for handler in list(root.handlers):
        if getattr(handler, "_saas_readiness_json", False):
            root.removeHandler(handler)
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter())
    handler._saas_readiness_json = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    return root
