# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The single place handlers obtain AWS clients (tests replace these two functions)."""

from __future__ import annotations

from typing import Any

import boto3

from drift_core.collectors import CLIENT_CONFIG


def client(service: str, region: str | None = None) -> Any:
    return boto3.client(service, region_name=region, config=CLIENT_CONFIG)


def assumed_client(service: str, region: str, credentials: dict[str, str]) -> Any:
    """A client built from sts:AssumeRole `Credentials` (cross-account journal reads, D§3.3a)."""
    return boto3.client(service, region_name=region, config=CLIENT_CONFIG,
                        aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"])


def table(name: str) -> Any:
    return boto3.resource("dynamodb", config=CLIENT_CONFIG).Table(name)
