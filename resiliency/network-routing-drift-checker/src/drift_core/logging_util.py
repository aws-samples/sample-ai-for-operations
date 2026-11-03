# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Structured JSON logging with a redaction list (design.md D§9).

Secrets (the webhook HMAC secret) and the webhook URL are registered with
`register_secret` and are replaced with '[REDACTED]' in every emitted line,
whether they appear as a field value or embedded in a message string.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

_REDACTED = "[REDACTED]"
_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    """Add a value that must never appear in logs. Short values are ignored to avoid over-redaction."""
    if value and len(value) >= 8:
        _secrets.add(value)


def clear_secrets() -> None:
    _secrets.clear()


def redact(text: str) -> str:
    for secret in sorted(_secrets, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, _REDACTED)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return redact(json.dumps(payload, default=str, sort_keys=True))


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.handlers = [handler]
        logger.propagate = False
    logger.setLevel(level)
    return logger


def log_event(logger: logging.Logger, event: str, level: int = logging.INFO, **fields: Any) -> None:
    """Emit one structured line: {'message': event, ...fields}."""
    logger.log(level, event, extra={"fields": fields})
