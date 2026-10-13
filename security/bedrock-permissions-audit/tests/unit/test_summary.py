# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from datetime import UTC, datetime

from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.models import Account, AccountResult
from bedrock_permissions_audit.scoring import score
from bedrock_permissions_audit.summary import (
    ASSUME_ROLE_NOTICE,
    CONDITION_NOTICE,
    SCP_NOTICE,
    account_breakout,
    collect_findings,
    summarize,
)

from .factories import ADMIN, credential, finding

CONFIG = Config()
NOW = datetime(2026, 6, 1, tzinfo=UTC)


def critical(account_id):
    return score(finding(account_id=account_id, admin_policies=(ADMIN,)), CONFIG)


def high(account_id):
    return score(finding(account_id=account_id, credential=credential(unused_days=300)), CONFIG)


def hidden_info(account_id):
    return score(finding(account_id=account_id, results=(), grant="none"), CONFIG)


def account(account_id, findings, status="ok", **kwargs):
    return AccountResult(
        Account(account_id, f"name-{account_id}"),
        status,
        findings=tuple(findings),
        principals_evaluated=len(findings),
        **kwargs,
    )


def test_e23_breakout_puts_the_account_with_most_critical_findings_first():
    results = [
        account("333333333333", [high("333333333333")] * 5),
        account("111111111111", [critical("111111111111")]),
        account("222222222222", [critical("222222222222")] * 3),
    ]

    rows = account_breakout(results, CONFIG)

    assert [r.account_id for r in rows] == ["222222222222", "111111111111", "333333333333"]
    assert rows[0].tier_counts["Critical"] == 3
    assert rows[2].tier_counts["High"] == 5


def test_e23_ties_break_on_high_then_account_id():
    results = [
        account("999999999999", [critical("999999999999")]),
        account("222222222222", [critical("222222222222")]),
        account("555555555555", [critical("555555555555"), high("555555555555")]),
    ]

    rows = account_breakout(results, CONFIG)

    assert [r.account_id for r in rows] == ["555555555555", "222222222222", "999999999999"]


def test_breakout_counts_only_visible_findings():
    result = account("111111111111", [critical("111111111111"), hidden_info("111111111111")])

    (row,) = account_breakout([result], CONFIG)

    assert row.tier_counts["Critical"] == 1
    assert row.tier_counts["Info"] == 0
    assert row.principals_evaluated == 2


def test_breakout_with_one_account_still_has_one_row():
    rows = account_breakout([account("111111111111", [])], CONFIG)

    assert len(rows) == 1
    assert sum(rows[0].tier_counts.values()) == 0


def test_partial_accounts_count_as_scanned_and_are_listed_separately():
    generated = datetime(2026, 6, 1, 8, 30, tzinfo=UTC)
    results = [
        account("111111111111", [critical("111111111111")]),
        account(
            "222222222222",
            [high("222222222222")],
            status="partial",
            reason="API keys not evaluated",
            credential_report_generated_at=generated,
        ),
        AccountResult(Account("333333333333"), "failed", reason="AssumeRoleError: denied"),
    ]

    summary = summarize("org", NOW, NOW, results, CONFIG)

    assert (summary.accounts_scanned, summary.accounts_partial, summary.accounts_failed) == (
        2,
        1,
        1,
    )
    assert summary.partial_accounts == [
        {
            "account_id": "222222222222",
            "name": "name-222222222222",
            "reason": "API keys not evaluated",
        }
    ]
    assert [a.status for a in summary.accounts] == ["ok", "partial"]
    assert summary.accounts[1].credential_report_generated_at == generated
    assert summary.principals_evaluated == 2


def test_partial_account_findings_are_reported():
    results = [account("222222222222", [high("222222222222")], status="partial")]

    assert len(collect_findings(results, CONFIG)) == 1


def test_every_run_carries_the_limitation_notices():
    summary = summarize("single", NOW, NOW, [], CONFIG)

    assert SCP_NOTICE in summary.notices
    assert ASSUME_ROLE_NOTICE in summary.notices
    assert CONDITION_NOTICE in summary.notices
    assert "Resource Control Policies" in SCP_NOTICE
