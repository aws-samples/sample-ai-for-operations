# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Decide which accounts to audit and obtain a read-only session for each."""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import Literal

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from . import __version__
from .config import DEFAULT_ROLE_NAME, Config
from .models import Account

logger = logging.getLogger(__name__)

SESSION_NAME = "bedrock-permissions-audit"
DEFAULT_ROLE_HINT = (
    " The default audit role may not be deployed in this account: deploy infra/audit-role.yaml"
    " (for example as a StackSet) or pass --role-name."
)
_NO_ORG_ERRORS = {
    "AccessDeniedException",
    "AWSOrganizationsNotInUseException",
    "AccessDenied",
}


class DiscoveryError(RuntimeError):
    """Raised when no account can be audited at all. The CLI maps this to exit code 2."""


class AssumeRoleError(RuntimeError):
    """Raised for one member account. The run continues; the account is reported as failed."""


def boto_config() -> BotoConfig:
    """Adaptive retries on every client so IAM throttling slows the run instead of failing it."""
    return BotoConfig(
        retries={"mode": "adaptive", "max_attempts": 10},
        user_agent_extra=f"bedrock-permissions-audit/{__version__}",
    )


@dataclass(frozen=True)
class Discovery:
    mode: Literal["org", "single"]
    accounts: tuple[Account, ...]
    caller_account_id: str
    partition: str
    notice: str | None = None


def discover(config: Config, session: boto3.Session) -> Discovery:
    """Work out the mode and the account list. Raises DiscoveryError on unusable credentials."""
    sts = session.client("sts", config=boto_config())
    try:
        identity = sts.get_caller_identity()
    except (ClientError, BotoCoreError) as exc:
        raise DiscoveryError(f"Cannot determine caller identity: {_reason(exc)}") from exc

    caller_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]
    single = Discovery(
        mode="single",
        accounts=(Account(account_id=caller_id, is_caller=True),),
        caller_account_id=caller_id,
        partition=partition,
    )
    if config.mode == "single":
        return single

    try:
        accounts = _list_active_accounts(session, caller_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in _NO_ORG_ERRORS:
            raise DiscoveryError(f"Cannot list organization accounts: {_reason(exc)}") from exc
        if config.mode == "org":
            raise DiscoveryError(
                "mode=org was requested but the caller cannot list organization accounts "
                f"({code}). Run from the management or a delegated administrator account."
            ) from exc
        notice = (
            f"Not permitted to list organization accounts ({code}); "
            f"auditing only account {caller_id}."
        )
        logger.warning("fallback_to_single_account", extra={"reason": code})
        return replace(single, notice=notice)

    # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
    if not any(a.is_caller for a in accounts):
        # The caller's account is not an ACTIVE org member (unusual). Still audit it directly.
        accounts = [Account(account_id=caller_id, is_caller=True), *accounts]
    return Discovery(
        mode="org",
        accounts=tuple(accounts),
        caller_account_id=caller_id,
        partition=partition,
    )


def _list_active_accounts(session: boto3.Session, caller_id: str) -> list[Account]:
    organizations = session.client("organizations", config=boto_config())
    accounts: list[Account] = []
    for page in organizations.get_paginator("list_accounts").paginate():
        for item in page["Accounts"]:
            if item.get("Status") != "ACTIVE":
                continue
            accounts.append(
                Account(
                    account_id=item["Id"],
                    name=item.get("Name"),
                    is_caller=item["Id"] == caller_id,
                )
            )
    return accounts


class SessionFactory:
    """Creates one boto3 session per account. The shared STS client is thread-safe; sessions
    are built per call so worker threads never share a Session."""

    def __init__(self, config: Config, base_session: boto3.Session, discovery: Discovery):
        self._config = config
        self._base = base_session
        self._partition = discovery.partition
        self._sts = base_session.client("sts", config=boto_config())

    def for_account(self, account: Account) -> boto3.Session:
        # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
        if account.is_caller:
            return self._base
        role_arn = f"arn:{self._partition}:iam::{account.account_id}:role/{self._config.role_name}"
        params: dict[str, object] = {
            "RoleArn": role_arn,
            "RoleSessionName": SESSION_NAME,
            "DurationSeconds": 3600,
        }
        if self._config.external_id:
            params["ExternalId"] = self._config.external_id
        try:
            credentials = self._sts.assume_role(**params)["Credentials"]
        except (ClientError, BotoCoreError) as exc:
            message = f"Cannot assume {role_arn}: {_reason(exc)}"
            if self._config.role_name == DEFAULT_ROLE_NAME:
                message += DEFAULT_ROLE_HINT
            raise AssumeRoleError(message) from exc
        # IAM is a global service; a fixed Region only selects its endpoint.
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name="us-east-1",
        )


def _reason(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        return f"{error.get('Code', 'Error')}: {error.get('Message', '')}".strip()
    return str(exc)
