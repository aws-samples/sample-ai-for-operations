# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Structured logging and secret redaction (design D§9, requirements §14.4)."""

import json
import logging

import pytest

from drift_core.logging_util import clear_secrets, get_logger, log_event, redact, register_secret

SECRET = "s3cr3t-hmac-value-0123456789"  # nosec B105 -- fixed test vector for the redaction-list test, not a real secret
URL = "https://event-ai.eu-central-1.api.aws/webhook/generic/abc123"


@pytest.fixture(autouse=True)
def _reset():
    clear_secrets()
    yield
    clear_secrets()


def test_redacts_registered_values_in_fields_and_message(capsys):
    register_secret(SECRET)
    register_secret(URL)
    log = get_logger("t.redact")
    log_event(log, f"posting to {URL}", run_id="r1", header=f"sig={SECRET}")
    line = capsys.readouterr().out.strip()
    assert SECRET not in line and URL not in line
    record = json.loads(line)
    assert record["run_id"] == "r1"
    assert record["message"] == "posting to [REDACTED]"


def test_short_values_not_registered():
    register_secret("abc")
    assert redact("abc") == "abc"


def test_exception_is_logged_and_redacted(capsys):
    register_secret(SECRET)
    log = get_logger("t.exc")
    try:
        raise RuntimeError(f"boom {SECRET}")
    except RuntimeError:
        log.exception("failed")
    line = capsys.readouterr().out.strip()
    assert SECRET not in line and "RuntimeError" in line


def test_handler_not_duplicated():
    a = get_logger("t.dup")
    b = get_logger("t.dup", "DEBUG")
    assert a is b and len(b.handlers) == 1 and b.level == logging.DEBUG
