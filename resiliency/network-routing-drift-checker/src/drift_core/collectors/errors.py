# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Classify AWS errors raised during collection (tasks.md 1.15).

The exception CLASS NAME becomes the Step Functions error name, so the state machine can
retry only what can succeed on retry, and the report can say why a Region was not evaluated.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError, ConnectionError, ReadTimeoutError

_THROTTLE = {"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException",
             "RequestThrottled", "RequestThrottledException", "SlowDown", "LimitExceededException"}
_TRANSIENT = {"InternalError", "InternalFailure", "InternalServerException", "ServiceUnavailable",
              "ServiceUnavailableException", "DirectConnectServerException", "RequestTimeout"}
_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure", "OptInRequired",
           "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredToken"}


class CollectionThrottled(Exception):
    """Throttled or transient service error. Retried by the state machine."""


class CollectionAccessDenied(Exception):
    """Denied by IAM, an SCP, or a Region that is not enabled. Not retried."""


class CollectionApiError(Exception):
    """Any other API error. Not retried."""


HINTS = {
    "CollectionThrottled": "throttled or service unavailable after retries",
    "CollectionAccessDenied": "access denied; check IAM permissions, SCPs and whether the Region is enabled",
    "CollectionApiError": "AWS API error",
    "States.Timeout": "collection timed out",
}


def classify(exc: Exception) -> Exception:
    """Map a botocore exception to one of the three collection errors (message carries the AWS code)."""
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = error.get("Code", "Unknown")
        op = getattr(exc, "operation_name", "")
        text = f"{code} on {op}" if op else code
        if code in _THROTTLE or code in _TRANSIENT:
            return CollectionThrottled(text)
        if code in _DENIED:
            return CollectionAccessDenied(text)
        return CollectionApiError(text)
    if isinstance(exc, (ReadTimeoutError, ConnectionError)):
        return CollectionThrottled(type(exc).__name__)
    return CollectionApiError(type(exc).__name__)


def classified[F: Callable[..., Any]](fn: F) -> F:
    """Decorator for collection handlers: re-raise AWS errors as classified collection errors."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            # nosemgrep: return-not-in-function -- inside wrapper(); see classified()'s docstring above
            return fn(*args, **kwargs)
        except (ClientError, BotoCoreError) as exc:
            raise classify(exc) from exc

    return wrapper  # type: ignore[return-value]  # nosemgrep: return-not-in-function, code-after-unconditional-return -- same PEP 695 parser-scope issue; this is the correctly-placed decorator return


def describe(error_name: str) -> str:
    """Human-readable reason for a Step Functions error name (falls back to the name)."""
    return f"{HINTS[error_name]} ({error_name})" if error_name in HINTS else error_name
