# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Shared test helpers. No test contacts AWS: clients are either stubbed or served by moto."""

from __future__ import annotations

import os

import boto3
import pytest
from botocore.stub import Stubber

# Dummy values so botocore never falls back to a real credential or profile on this machine.
_FAKE_ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",  # noqa: S105
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
}


@pytest.fixture(autouse=True)
def _isolated_aws_environment(monkeypatch):
    for key, value in _FAKE_ENV.items():
        monkeypatch.setenv(key, value)
    for key in ("AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)


class StubbedSession:
    """Looks like a boto3.Session. Each service client is created once and wrapped in a Stubber
    so tests queue exact responses and assert that nothing unexpected was called."""

    def __init__(self) -> None:
        self._session = boto3.Session(region_name="us-east-1")
        self._clients: dict[str, object] = {}
        self._stubbers: dict[str, Stubber] = {}

    def client(self, service: str, config=None, **_kwargs):
        if service not in self._clients:
            client = self._session.client(service, config=config)
            stubber = Stubber(client)
            stubber.activate()
            self._clients[service] = client
            self._stubbers[service] = stubber
        return self._clients[service]

    def stubber(self, service: str) -> Stubber:
        self.client(service)
        return self._stubbers[service]

    def assert_all_consumed(self) -> None:
        for stubber in self._stubbers.values():
            stubber.assert_no_pending_responses()


@pytest.fixture
def stubbed_session() -> StubbedSession:
    return StubbedSession()
