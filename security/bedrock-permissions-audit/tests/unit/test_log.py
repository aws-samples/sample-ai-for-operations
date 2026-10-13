# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import base64
import io
import json

import pytest

from bedrock_permissions_audit.log import configure_logging, redact

# AWS documentation example key ID; not a real credential.
KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
API_KEY = "ABSK" + base64.b64encode(b"BedrockAPIKey-example-12345678").decode()


def capture(emit) -> list[dict]:
    stream = io.StringIO()
    logger = configure_logging("DEBUG", stream)
    emit(logger)
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_output_is_json_lines_with_expected_fields():
    (record,) = capture(lambda log: log.info("account_done", extra={"account_id": "123456789012"}))
    assert record["level"] == "INFO"
    assert record["event"] == "account_done"
    assert record["account_id"] == "123456789012"
    assert record["ts"].endswith("+00:00")


def test_key_id_in_message_is_masked():
    (record,) = capture(lambda log: log.warning("found key %s", KEY_ID))
    assert KEY_ID not in json.dumps(record)
    assert record["event"].endswith("...MPLE")


def test_key_id_in_extra_field_is_masked():
    (record,) = capture(lambda log: log.info("finding", extra={"key": KEY_ID}))
    assert KEY_ID not in json.dumps(record)
    assert record["key"] == "...MPLE"


def test_api_key_token_is_redacted_everywhere():
    (record,) = capture(lambda log: log.error("bad token %s", API_KEY, extra={"tok": API_KEY}))
    assert API_KEY not in json.dumps(record)
    assert record["tok"] == "[REDACTED]"


def test_key_id_in_exception_traceback_is_masked():
    def emit(log):
        try:
            raise RuntimeError(f"failed for {KEY_ID}")
        except RuntimeError:
            log.exception("boom")

    (record,) = capture(emit)
    assert KEY_ID not in json.dumps(record)
    assert "...MPLE" in record["exception"]


def test_level_filters_records():
    stream = io.StringIO()
    logger = configure_logging("ERROR", stream)
    logger.info("hidden")
    logger.error("shown")
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "shown"


@pytest.mark.parametrize(
    "text", ["nothing secret here", "AKIA", "arn:aws:iam::123456789012:user/a"]
)
def test_ordinary_text_is_untouched(text):
    assert redact(text) == text
