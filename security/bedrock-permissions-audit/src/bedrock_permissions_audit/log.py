# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Structured JSON-lines logging to stderr with defensive redaction of credential material."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

# IAM access key IDs (AKIA..., ASIA...) and the Amazon Bedrock / Claude Platform API key prefixes.
_ACCESS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA|AIDA|AGPA|AROA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{12,}\b")
_API_KEY_TOKEN = re.compile(
    r"\b(?:ABSK|AEAA|bedrock-api-key-|aws-external-anthropic-api-key-)[A-Za-z0-9+/=_\-]{8,}"
)

_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime"}


def redact(text: str) -> str:
    """Mask anything shaped like a key ID or API key. Defence in depth: callers should not log
    these in the first place."""
    text = _ACCESS_KEY_ID.sub(lambda m: "..." + m.group(0)[-4:], text)
    return _API_KEY_TOKEN.sub("[REDACTED]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="seconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": redact(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = redact(value) if isinstance(value, str) else value
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", stream: Any = None) -> logging.Logger:
    logger = logging.getLogger("bedrock_permissions_audit")
    logger.setLevel(level.upper())
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger
