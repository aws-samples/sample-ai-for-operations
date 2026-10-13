# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Audit one account: collect, evaluate, score. This is the unit the runner parallelises."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

from .accounts import SessionFactory, boto_config
from .collectors import api_keys as api_key_collector
from .collectors.api_keys import is_access_denied, is_phantom_user
from .collectors.credential_report import fetch_credential_report_with_time
from .collectors.iam_users import collect_principals, list_user_names
from .config import Config
from .evaluator import Evaluation, Evaluator, SimulatorEvaluator, safe_evaluate
from .models import Account, AccountResult, Finding, Principal
from .scoring import score

logger = logging.getLogger(__name__)

EvaluatorFactory = Callable[[Any, Config], Evaluator]

API_KEYS_NOT_EVALUATED = (
    "Amazon Bedrock API keys not evaluated: iam:ListServiceSpecificCredentials was denied"
)
# IAM may reuse a report up to four hours old. Beyond this, the root access key data is stale
# enough to be worth a warning. A constant, not a setting: it describes IAM, not a customer choice.
STALE_REPORT = timedelta(hours=1)


def build_findings(
    account: Account, principal: Principal, evaluation: Evaluation, config: Config
) -> list[Finding]:
    """One finding per credential. A BedrockAPIKey-* / AeaApiKey-* user with no active
    credential becomes a single 'orphaned' finding instead."""
    base = {
        "account_id": account.account_id,
        "account_name": account.name,
        "principal_arn": principal.arn,
        "principal_name": principal.name,
        "mfa_active": principal.mfa_active,
        # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
        "is_root": principal.is_root,
        # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
        "is_phantom": principal.is_phantom,
        "admin_policies": tuple(
            arn for arn in principal.attached_policy_arns if arn in config.admin_policy_arns
        ),
        "results": evaluation.results,
        "grant": evaluation.grant,
        "regions_allowed": evaluation.regions_allowed,
        "warnings": evaluation.warnings,
    }
    # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
    if principal.is_phantom and not any(c.active for c in principal.credentials):
        return [score(Finding(**base, credential=None, orphaned=True), config)]
    return [score(Finding(**base, credential=c), config) for c in principal.credentials]


def audit_account(
    account: Account,
    session: boto3.Session,
    config: Config,
    now: datetime,
    evaluator_factory: EvaluatorFactory = SimulatorEvaluator,
) -> AccountResult:
    iam = session.client("iam", config=boto_config())
    report, report_generated = fetch_credential_report_with_time(iam)

    warnings: list[str] = []
    stale = _stale_report_warning(report_generated, now)
    if stale:
        warnings.append(stale)

    partial_reason: str | None = None
    try:
        bedrock_keys, key_warnings = api_key_collector.collect_bedrock_api_keys(iam, now)
        warnings.extend(key_warnings)
    except ClientError as exc:
        if not is_access_denied(exc):
            raise
        # The role lacks this one read. Everything else is still valid, so audit the account
        # without its API keys and say so, rather than failing it or hiding the gap.
        partial_reason = API_KEYS_NOT_EVALUATED
        bedrock_keys = {}
        logger.warning("api_key_listing_denied", extra={"account_id": account.account_id})

    if partial_reason:
        keys = {}
    else:
        # API key users (BedrockAPIKey-*, AeaApiKey-*) are always listed per user. Claude Platform
        # keys have no account-wide listing, and for Amazon Bedrock this is the fallback that keeps
        # the console-created users covered when the account-wide call is unavailable. Duplicates
        # merge.
        api_key_users = [name for name in list_user_names(iam) if is_phantom_user(name)]
        per_user_keys = api_key_collector.collect_user_api_keys(iam, api_key_users, now)
        keys = api_key_collector.merge(bedrock_keys, per_user_keys)

    principals, notes = collect_principals(iam, account.account_id, report, keys, now)
    warnings = [*warnings, *notes]

    evaluator = evaluator_factory(iam, config)
    findings: list[Finding] = []
    for principal in principals:
        evaluation = safe_evaluate(evaluator, principal)
        warnings.extend(w for w in evaluation.warnings if w not in warnings)
        findings.extend(build_findings(account, principal, evaluation, config))

    logger.info(
        "account_audited",
        extra={
            "account_id": account.account_id,
            "principals": len(principals),
            "findings": len(findings),
        },
    )
    return AccountResult(
        account=account,
        status="partial" if partial_reason else "ok",
        reason=partial_reason,
        findings=tuple(findings),
        principals_evaluated=len(principals),
        warnings=tuple(warnings),
        credential_report_generated_at=report_generated,
    )


def _stale_report_warning(generated: datetime | None, now: datetime) -> str | None:
    if generated is None or generated.tzinfo is None or now.tzinfo is None:
        return None
    if now - generated <= STALE_REPORT:
        return None
    return (
        f"The IAM credential report was generated at {generated:%Y-%m-%d %H:%M} UTC; "
        "a root access key created since then is not visible."
    )


def make_worker(
    config: Config,
    factory: SessionFactory,
    now: datetime,
    evaluator_factory: EvaluatorFactory = SimulatorEvaluator,
) -> Callable[[Account], AccountResult]:
    def worker(account: Account) -> AccountResult:
        session = factory.for_account(account)
        return audit_account(account, session, config, now, evaluator_factory)

    return worker
