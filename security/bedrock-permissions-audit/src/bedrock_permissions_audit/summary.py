# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Run summary. Every number is computed from the findings, never typed by hand."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from .config import Config
from .models import AccountBreakout, AccountResult, Finding, RunSummary, Tier
from .scoring.ordering import (
    CANNOT_INVOKE,
    INACTIVE_OR_EXPIRED,
    hidden_reason,
    is_visible,
    sort_findings,
)

SCP_NOTICE = (
    "Results come from the IAM policy simulator, which evaluates identity-based policies only. "
    "It does not evaluate Service Control Policies or Resource Control Policies, so a principal "
    "shown as able to invoke Amazon Bedrock may be blocked at the organization level."
)
ASSUME_ROLE_NOTICE = (
    "Access reached through sts:AssumeRole is not followed. A user whose own policy cannot invoke "
    "Amazon Bedrock, but who can assume a role that can, is reported as unable to invoke."
)
CONDITION_NOTICE = (
    "A grant that depends on request context (source IP, VPC, tags) may be shown as allowed. "
    "missing_context in findings.json lists the condition keys the simulator had no value for."
)
SCOPE_NOTICE = (
    "Only long-lived credentials are audited (IAM user access keys, root access keys, and "
    "long-term Amazon Bedrock and Claude Platform on AWS API keys). Roles are out of scope."
)


def collect_findings(results: Iterable[AccountResult], config: Config) -> list[Finding]:
    """Visible findings from every successful account, in report order."""
    every = [f for r in results if r.audited for f in r.findings]
    return sort_findings([f for f in every if is_visible(f, config)], config)


def summarize(
    mode: str,
    started_at: datetime,
    finished_at: datetime,
    results: list[AccountResult],
    config: Config,
    notices: Iterable[str] = (),
) -> RunSummary:
    ok = [r for r in results if r.audited]  # complete and partial: both have findings
    partial = [r for r in ok if r.status == "partial"]
    failed = [r for r in results if r.status == "failed"]
    every = [f for r in ok for f in r.findings]
    visible = [f for f in every if is_visible(f, config)]

    counts = {tier.label: 0 for tier in Tier}
    for finding in visible:
        counts[finding.tier.label] += 1

    hidden_by_reason = {CANNOT_INVOKE: 0, INACTIVE_OR_EXPIRED: 0}
    for finding in every:
        if not is_visible(finding, config):
            hidden_by_reason[hidden_reason(finding)] += 1

    warnings: dict[str, None] = {}
    for result in ok:
        for warning in result.warnings:
            warnings[f"{result.account.account_id}: {warning}"] = None

    return RunSummary(
        mode="org" if mode == "org" else "single",
        started_at=started_at,
        finished_at=finished_at,
        accounts_scanned=len(ok),
        accounts_failed=len(failed),
        failed_accounts=[
            {
                "account_id": r.account.account_id,
                "name": r.account.name or "",
                "reason": r.reason or "unknown error",
            }
            for r in sorted(failed, key=lambda r: r.account.account_id)
        ],
        accounts_partial=len(partial),
        partial_accounts=[
            {
                "account_id": r.account.account_id,
                "name": r.account.name or "",
                "reason": r.reason or "evaluation incomplete",
            }
            for r in sorted(partial, key=lambda r: r.account.account_id)
        ],
        accounts=account_breakout(ok, config),
        principals_evaluated=sum(r.principals_evaluated for r in ok),
        tier_counts=counts,
        hidden_info=len(every) - len(visible),
        hidden_info_by_reason=hidden_by_reason,
        warnings=list(warnings),
        notices=[*notices, SCP_NOTICE, ASSUME_ROLE_NOTICE, CONDITION_NOTICE, SCOPE_NOTICE],
    )


def account_breakout(results: Iterable[AccountResult], config: Config) -> list[AccountBreakout]:
    """One row per audited account, the account with the most Critical findings first."""
    rows = []
    for result in results:
        counts = {tier.label: 0 for tier in Tier}
        for finding in result.findings:
            if is_visible(finding, config):
                counts[finding.tier.label] += 1
        rows.append(
            AccountBreakout(
                account_id=result.account.account_id,
                name=result.account.name,
                status="partial" if result.status == "partial" else "ok",
                principals_evaluated=result.principals_evaluated,
                tier_counts=counts,
                credential_report_generated_at=result.credential_report_generated_at,
            )
        )
    rows.sort(key=lambda r: (-r.tier_counts["Critical"], -r.tier_counts["High"], r.account_id))
    return rows
