# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Schema for ``intent.yaml``: customer-named networks, destination buckets, and the baseline."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .fileio import read_text


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NamedNetwork(_Strict):
    name: str
    kind: Literal["on-premises", "partner", "saas", "vpc", "other"] = "other"
    cidrs: list[str]

    @field_validator("cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        for c in v:
            ipaddress.ip_network(c, strict=False)
        if not v:
            raise ValueError("a network needs at least one CIDR")
        return v


class BucketMatch(_Strict):
    services: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    classes: list[str] = Field(default_factory=list)  # destination classes, e.g. aws-service
    networks: list[str] = Field(default_factory=list)
    aws_service: bool | None = None
    default: bool = False


class Bucket(_Strict):
    name: str
    match: BucketMatch
    disposition: Literal["allow", "review", "inspect"] = "review"


class Endpoint(_Strict):
    network: str | None = None
    bucket: str | None = None
    service: str | None = None
    port: int | None = None
    path: str | None = None
    workload: str | None = None
    cidr: str | None = None


class Evidence(_Strict):
    bytes: int = 0
    conversations: int = 0
    first_seen: str = ""
    last_seen: str = ""


class BaselineEntry(_Strict):
    consumer: Endpoint
    provider: Endpoint
    evidence: Evidence = Field(default_factory=Evidence)


class Intent(_Strict):
    version: Literal[1] = 1
    networks: list[NamedNetwork] = Field(default_factory=list)
    buckets: list[Bucket] = Field(default_factory=list)
    baseline: list[BaselineEntry] = Field(default_factory=list)


def load_intent(path: str | Path, s3: object = None) -> Intent:
    return Intent.model_validate(yaml.safe_load(read_text(str(path), s3)) or {})


def dump_intent(intent: Intent) -> str:
    return yaml.safe_dump(intent.model_dump(exclude_none=True), sort_keys=False, default_flow_style=False)
