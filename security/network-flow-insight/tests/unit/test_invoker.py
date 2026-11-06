# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The scheduler's target Lambda must fail when the runtime reports a failure, so the error alarm can fire."""

import importlib.util
import io
import json
import logging
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


class _FakeClient:
    def __init__(self, body: bytes):
        self.body = body
        self.calls: list[dict] = []

    def invoke_agent_runtime(self, **kw):
        self.calls.append(kw)
        return {"response": io.BytesIO(self.body)}


def _load(monkeypatch, reply):
    """Load infra/lambda/invoker.py with a fake boto3 client, so no credentials or Region are needed."""
    body = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
    fake = _FakeClient(body)
    monkeypatch.setattr("boto3.client", lambda *_a, **_k: fake)
    monkeypatch.setenv("RUNTIME_ARN", "arn:aws:bedrock-agentcore:eu-west-2:123456789012:runtime/example")
    spec = importlib.util.spec_from_file_location("nfi_invoker", ROOT / "infra" / "lambda" / "invoker.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, fake


def test_a_successful_run_returns_ok(monkeypatch):
    mod, fake = _load(monkeypatch, {"mode": "describe", "scan": {}})
    assert mod.handler({"mode": "describe"}, None) == {"mode": "describe", "status": "ok"}
    assert json.loads(fake.calls[0]["payload"]) == {"mode": "describe"}


def test_a_runtime_error_reply_raises_without_logging_an_error(monkeypatch, caplog):
    # Lambda records the raised exception itself, so a separate ERROR log line would only duplicate it.
    mod, _ = _load(monkeypatch, {"error": "invocation failed; see logs"})
    with caplog.at_level(logging.DEBUG), pytest.raises(RuntimeError) as raised:
        mod.handler({"mode": "describe"}, None)
    assert "describe" in str(raised.value)
    assert "invocation failed" not in str(raised.value) + caplog.text  # the reply itself is never copied out
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


@pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'"text"', b""])
def test_a_reply_that_is_not_a_json_object_raises(monkeypatch, caplog, body):
    mod, _ = _load(monkeypatch, body)
    with caplog.at_level(logging.DEBUG), pytest.raises(RuntimeError) as raised:
        mod.handler({"mode": "drift"}, None)
    assert "drift" in str(raised.value)
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


@pytest.mark.parametrize("marker", ["agent_error", "fallback"])
def test_a_degraded_run_warns_but_succeeds(monkeypatch, caplog, marker):
    mod, _ = _load(monkeypatch, {"mode": "describe", marker: "x", "report": {}})
    with caplog.at_level(logging.WARNING):
        assert mod.handler({"mode": "describe"}, None) == {"mode": "describe", "status": "ok"}
    assert "scheduled_run_degraded" in caplog.text


def test_a_bad_mode_is_rejected_before_any_call(monkeypatch):
    mod, fake = _load(monkeypatch, {})
    with pytest.raises(ValueError):
        mod.handler({"mode": "chat"}, None)
    assert fake.calls == []
