# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Resilience helper for live/regional AWS calls.

Real-world failure modes this handles (documented BYOC cases):
  * a regional endpoint unreachable from the network (e.g. me-south-1 EC2
    endpoint unreachable for months);
  * a Service Control Policy denying a Describe call outside a whitelist;
  * ordinary connect/read timeouts.

On any of these, the live call is treated as "unavailable" so the caller can
fall back to the account-independent primary source instead of raising.
"""

from typing import Callable, Optional, TypeVar

from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
)
from botocore.exceptions import (
    ConnectionError as BotoConnectionError,
)

from logging_util import log_event

T = TypeVar("T")

# ClientError codes that mean "this live call will not work here" -> fall back.
_FALLBACK_ERROR_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "OptInRequired",
    "RequestExpired",
}


def try_live(
    call: Callable[[], T],
    *,
    dataset: str,
    region: Optional[str] = None,
) -> Optional[T]:
    """Run a live AWS call, returning None if it is unavailable.

    Returns the call result on success, or None if the endpoint is unreachable
    or the call is denied (SCP / opt-in), signalling the caller to fall back.
    Unexpected ClientErrors are re-raised so genuine bugs are not masked.
    """
    try:
        return call()
    except (EndpointConnectionError, BotoConnectionError) as exc:
        log_event(
            "live_call_unreachable",
            dataset=dataset,
            region=region,
            detail=type(exc).__name__,
        )
        return None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _FALLBACK_ERROR_CODES:
            log_event(
                "live_call_denied",
                dataset=dataset,
                region=region,
                error_code=code,
            )
            return None
        # Region-not-enabled surfaces in various ways; treat as fallback too.
        if "not enabled" in str(exc).lower() or "could not connect" in str(exc).lower():
            log_event("live_call_region_unavailable", dataset=dataset, region=region)
            return None
        raise
