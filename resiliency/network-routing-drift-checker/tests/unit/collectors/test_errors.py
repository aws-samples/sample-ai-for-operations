# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Collection error classification (tasks.md 1.15; found by the live fault-injection run)."""

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError

from drift_core.collectors.errors import (
    CollectionAccessDenied,
    CollectionApiError,
    CollectionThrottled,
    classified,
    classify,
    describe,
)


def err(code, op="DescribeTransitGateways"):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, op)


@pytest.mark.parametrize("code,cls", [
    ("ThrottlingException", CollectionThrottled), ("RequestLimitExceeded", CollectionThrottled),
    ("ServiceUnavailable", CollectionThrottled), ("UnauthorizedOperation", CollectionAccessDenied),
    ("AccessDeniedException", CollectionAccessDenied), ("OptInRequired", CollectionAccessDenied),
    ("InvalidParameterValue", CollectionApiError),
])
def test_classify_client_errors(code, cls):
    out = classify(err(code))
    assert isinstance(out, cls) and str(out) == f"{code} on DescribeTransitGateways"


def test_classify_network_and_other():
    assert isinstance(classify(ReadTimeoutError(endpoint_url="x")), CollectionThrottled)
    assert isinstance(classify(EndpointConnectionError(endpoint_url="x")), CollectionThrottled)
    assert isinstance(classify(ValueError("x")), CollectionApiError)


def test_decorator_reraises_classified_and_passes_others():
    @classified
    def denied():
        raise err("UnauthorizedOperation")

    @classified
    def bad_input():
        raise ValueError("not an AWS error")

    with pytest.raises(CollectionAccessDenied) as info:
        denied()
    assert isinstance(info.value.__cause__, ClientError)
    with pytest.raises(ValueError):
        bad_input()


def test_describe():
    assert describe("CollectionAccessDenied").startswith("access denied; check IAM permissions")
    assert describe("States.Timeout") == "collection timed out (States.Timeout)"
    assert describe("Something.Else") == "Something.Else"
