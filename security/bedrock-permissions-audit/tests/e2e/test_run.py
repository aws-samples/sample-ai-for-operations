# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Whole runs: Organizations discovery, role assumption, checkpoints, outputs and exit codes.

moto serves Organizations, STS and IAM across several accounts. The IAM policy simulator and the
account-wide API key listing are not available in moto, so those are replaced."""

import csv
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from bedrock_permissions_audit import audit as audit_module
from bedrock_permissions_audit.accounts import DiscoveryError
from bedrock_permissions_audit.app import EXIT_ALL_FAILED, EXIT_OK, run_audit
from bedrock_permissions_audit.checkpoint import CheckpointError
from bedrock_permissions_audit.collectors.credential_report import CredentialReportTimeout
from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.evaluator import SimulatorEvaluator
from bedrock_permissions_audit.output.terminal import render_report

from ..evaluator.fake_simulator import FakeIam, allow

# Every user in every account can invoke Amazon Bedrock on any model.
POLICY = [allow(["bedrock:InvokeModel"])]


class RecordingEvaluator:
    """Fake simulator that records which accounts were evaluated."""

    seen: list[str] = []

    def __init__(self, iam, config):
        self._inner = SimulatorEvaluator(FakeIam(POLICY), config)

    def evaluate(self, principal):
        RecordingEvaluator.seen.append(principal.account_id)
        return self._inner.evaluate(principal)


class BrokenRoleSts:
    """Real STS client, except assuming a role in one chosen account is denied."""

    def __init__(self, client, bad_account):
        self._client = client
        self._bad = bad_account

    def __getattr__(self, name):
        return getattr(self._client, name)

    def assume_role(self, **params):
        if f":{self._bad}:" in params["RoleArn"]:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized to assume"}},
                "AssumeRole",
            )
        return self._client.assume_role(**params)


class SessionWithBrokenRole:
    def __init__(self, bad_account=None):
        self._real = boto3.Session(region_name="us-east-1")
        self._bad = bad_account

    def client(self, name, config=None):
        client = self._real.client(name, config=config)
        return BrokenRoleSts(client, self._bad) if name == "sts" and self._bad else client


def iam_in(account_id):
    """An IAM client acting inside a member account, via the same role the tool will assume."""
    sts = boto3.client("sts", region_name="us-east-1")
    credentials = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
        RoleSessionName="seed",
    )["Credentials"]
    return boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


@pytest.fixture
def org(monkeypatch):
    monkeypatch.setattr(
        audit_module.api_key_collector, "collect_bedrock_api_keys", lambda iam, now: ({}, [])
    )
    RecordingEvaluator.seen = []
    with mock_aws():
        organizations = boto3.client("organizations", region_name="us-east-1")
        organizations.create_organization(FeatureSet="ALL")
        for name in ("alpha", "beta"):
            organizations.create_account(AccountName=name, Email=f"{name}@example.com")
        accounts = {
            a["Name"]: a["Id"]
            for a in organizations.list_accounts()["Accounts"]
            if a["Status"] == "ACTIVE"
        }
        management = organizations.describe_organization()["Organization"]["MasterAccountId"]

        boto3.client("iam", region_name="us-east-1").create_user(UserName="mgmt-user")
        boto3.client("iam", region_name="us-east-1").create_access_key(UserName="mgmt-user")
        for name in ("alpha", "beta"):
            client = iam_in(accounts[name])
            client.create_user(UserName=f"{name}-user")
            client.create_access_key(UserName=f"{name}-user")
        yield {"management": management, "alpha": accounts["alpha"], "beta": accounts["beta"]}


def run(tmp_path, session=None, **settings):
    config = Config(output_dir=tmp_path / "out", **settings)
    return run_audit(
        config, session or SessionWithBrokenRole(), evaluator_factory=RecordingEvaluator
    )


def csv_rows(tmp_path):
    with (tmp_path / "out" / "findings.csv").open() as handle:
        return list(csv.DictReader(handle))


def test_org_run_audits_every_account_and_merges_results(org, tmp_path):
    outcome = run(tmp_path)

    assert outcome.exit_code == EXIT_OK
    assert outcome.summary.mode == "org"
    assert outcome.summary.accounts_scanned == 3
    assert outcome.summary.accounts_failed == 0
    assert {f.account_id for f in outcome.findings} == set(org.values())
    assert {r["principal"] for r in csv_rows(tmp_path)} == {"mgmt-user", "alpha-user", "beta-user"}


def test_outputs_are_all_written_and_agree(org, tmp_path):
    outcome = run(tmp_path)
    out = tmp_path / "out"

    document = json.loads((out / "findings.json").read_text())
    rows = csv_rows(tmp_path)

    assert len(outcome.findings) == len(document["findings"]) == len(rows) == 3
    assert [f["tier"].title() for f in document["findings"]] == [r["tier"] for r in rows]
    assert (out / "remediation" / "scp-deny-bedrock-to-iam-users.json").exists()
    assert (out / "remediation" / "README.txt").exists()


def test_e1_a_failed_role_assumption_is_reported_and_the_rest_still_audited(org, tmp_path):
    outcome = run(tmp_path, session=SessionWithBrokenRole(org["beta"]))

    assert outcome.exit_code == EXIT_OK  # partial failure is a result, not a crash
    assert outcome.summary.accounts_scanned == 2
    assert outcome.summary.accounts_failed == 1
    (failure,) = outcome.summary.failed_accounts
    assert failure["account_id"] == org["beta"]
    assert "AssumeRoleError" in failure["reason"]
    assert "AccessDenied" in failure["reason"]
    assert org["beta"] not in {f.account_id for f in outcome.findings}


def test_e13_resume_skips_completed_accounts_and_produces_the_full_result(org, tmp_path):
    first = run(tmp_path, session=SessionWithBrokenRole(org["beta"]))
    assert first.summary.accounts_failed == 1
    RecordingEvaluator.seen = []

    second = run(tmp_path, resume=True)

    assert set(RecordingEvaluator.seen) == {org["beta"]}  # nothing else was queried again
    assert second.summary.accounts_scanned == 3
    assert second.summary.accounts_failed == 0
    assert {r["principal"] for r in csv_rows(tmp_path)} == {"mgmt-user", "alpha-user", "beta-user"}
    assert any("Resumed: 2" in notice for notice in second.summary.notices)


def test_resumed_run_equals_an_uninterrupted_run(org, tmp_path):
    clean = run_audit(
        Config(output_dir=tmp_path / "clean"),
        SessionWithBrokenRole(),
        evaluator_factory=RecordingEvaluator,
    )
    run(tmp_path, session=SessionWithBrokenRole(org["beta"]))
    resumed = run(tmp_path, resume=True)

    assert [(f.account_id, f.principal_name, f.tier) for f in resumed.findings] == [
        (f.account_id, f.principal_name, f.tier) for f in clean.findings
    ]


def test_existing_results_are_not_overwritten_without_resume(org, tmp_path):
    run(tmp_path)

    with pytest.raises(CheckpointError, match="--resume"):
        run(tmp_path)


def test_every_member_role_failing_still_reports_the_caller_account(org, tmp_path):
    class DenyEveryRole(SessionWithBrokenRole):
        def client(self, name, config=None):
            client = self._real.client(name, config=config)
            if name != "sts":
                return client

            class Sts(BrokenRoleSts):
                def assume_role(self, **params):
                    raise ClientError(
                        {"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole"
                    )

            return Sts(client, None)

    outcome = run(tmp_path, session=DenyEveryRole())

    assert outcome.summary.accounts_failed == 2
    assert outcome.summary.accounts_scanned == 1  # the caller's own account needs no role
    assert outcome.exit_code == EXIT_OK
    assert (tmp_path / "out" / "findings.json").exists()


def test_no_account_audited_exits_3_but_still_writes_the_failure_report(tmp_path, monkeypatch):
    def timeout(iam):
        raise CredentialReportTimeout("IAM credential report not ready after 60 seconds")

    monkeypatch.setattr(audit_module, "fetch_credential_report_with_time", timeout)
    with mock_aws():
        outcome = run(tmp_path, mode="single")

    assert outcome.exit_code == EXIT_ALL_FAILED
    assert outcome.summary.accounts_scanned == 0
    (failure,) = outcome.summary.failed_accounts
    assert failure["reason"].startswith("CredentialReportTimeout")
    document = json.loads((tmp_path / "out" / "findings.json").read_text())
    assert document["run"]["failed_accounts"] == [failure]


class SessionWithoutOrganizationsAccess:
    """Real clients, except organizations:ListAccounts is denied to the caller."""

    def __init__(self):
        self._real = boto3.Session(region_name="us-east-1")

    def client(self, name, config=None):
        client = self._real.client(name, config=config)
        if name != "organizations":
            return client

        class Denied:
            def get_paginator(self, _operation):
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "not allowed"}},
                    "ListAccounts",
                )

        return Denied()


def test_e2_without_list_accounts_permission_falls_back_to_this_account(tmp_path, monkeypatch):
    monkeypatch.setattr(
        audit_module.api_key_collector, "collect_bedrock_api_keys", lambda iam, now: ({}, [])
    )
    with mock_aws():
        client = boto3.client("iam", region_name="us-east-1")
        client.create_user(UserName="solo")
        client.create_access_key(UserName="solo")

        outcome = run(tmp_path, session=SessionWithoutOrganizationsAccess())

    assert outcome.summary.mode == "single"
    assert outcome.summary.accounts_scanned == 1
    assert any("auditing only account" in notice for notice in outcome.summary.notices)
    assert [f.principal_name for f in outcome.findings] == ["solo"]


def test_org_mode_without_list_accounts_permission_is_an_error(tmp_path):
    with mock_aws(), pytest.raises(DiscoveryError, match="mode=org"):
        run(tmp_path, session=SessionWithoutOrganizationsAccess(), mode="org")


def test_single_mode_never_assumes_a_role(org, tmp_path):
    outcome = run(tmp_path, mode="single")

    assert outcome.summary.mode == "single"
    assert {f.account_id for f in outcome.findings} == {org["management"]}


def test_empty_account_writes_valid_empty_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(
        audit_module.api_key_collector, "collect_bedrock_api_keys", lambda iam, now: ({}, [])
    )
    with mock_aws():
        outcome = run(tmp_path, mode="single")

    assert outcome.exit_code == EXIT_OK
    assert outcome.findings == []
    assert csv_rows(tmp_path) == []
    assert json.loads((tmp_path / "out" / "findings.json").read_text())["findings"] == []


def test_output_directory_is_private(org, tmp_path):
    run(tmp_path)
    out = Path(tmp_path / "out")

    assert (out.stat().st_mode & 0o077) == 0
    assert ((out / "findings.csv").stat().st_mode & 0o077) == 0
    assert ((out / ".checkpoints").stat().st_mode & 0o077) == 0


def deny_api_key_listing_in(monkeypatch, bad_account):
    """Make iam:ListServiceSpecificCredentials fail with AccessDenied in one account only.

    The collector is called with an IAM client and no account ID, so the account being audited is
    remembered per worker thread."""
    current = threading.local()
    real = audit_module.audit_account

    def audit_account(account, *args, **kwargs):
        current.account_id = account.account_id
        return real(account, *args, **kwargs)

    def collect(iam, now):
        if current.account_id == bad_account:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
                "ListServiceSpecificCredentials",
            )
        return {}, []

    monkeypatch.setattr(audit_module, "audit_account", audit_account)
    monkeypatch.setattr(audit_module.api_key_collector, "collect_bedrock_api_keys", collect)


def test_e21_denied_api_key_listing_makes_the_account_partial_not_failed(
    org, tmp_path, monkeypatch
):
    iam_in(org["alpha"]).create_user(UserName="BedrockAPIKey-abc")
    deny_api_key_listing_in(monkeypatch, org["alpha"])

    outcome = run(tmp_path)

    assert outcome.exit_code == EXIT_OK
    summary = outcome.summary
    assert (summary.accounts_scanned, summary.accounts_partial, summary.accounts_failed) == (
        3,
        1,
        0,
    )
    (partial,) = summary.partial_accounts
    assert partial["account_id"] == org["alpha"]
    assert "ListServiceSpecificCredentials" in partial["reason"]
    assert not summary.failed_accounts
    # The partial account's other findings are still reported, and its API key user, whose keys
    # cannot be seen, shows as orphaned rather than being left out.
    in_alpha = {f.principal_name: f for f in outcome.findings if f.account_id == org["alpha"]}
    assert set(in_alpha) == {"alpha-user", "BedrockAPIKey-abc"}
    assert in_alpha["BedrockAPIKey-abc"].orphaned
    assert {a.account_id: a.status for a in summary.accounts} == {
        org["alpha"]: "partial",
        org["beta"]: "ok",
        org["management"]: "ok",
    }


def test_e21_partial_account_is_reported_in_terminal_and_json(org, tmp_path, monkeypatch):
    deny_api_key_listing_in(monkeypatch, org["alpha"])

    outcome = run(tmp_path)
    text = render_report(outcome.findings, outcome.summary, Config(output_dir=tmp_path / "out"))
    document = json.loads((tmp_path / "out" / "findings.json").read_text())

    assert "partial: 1" in text
    assert "Accounts audited with incomplete coverage" in text
    assert org["alpha"] in text.split("Accounts audited with incomplete coverage")[1]
    assert document["run"]["accounts_partial"] == 1
    assert document["run"]["partial_accounts"][0]["account_id"] == org["alpha"]
    statuses = {a["account_id"]: a["status"] for a in document["run"]["accounts"]}
    assert statuses[org["alpha"]] == "partial"


def test_e21_resume_audits_a_partial_account_again(org, tmp_path, monkeypatch):
    deny_api_key_listing_in(monkeypatch, org["alpha"])
    first = run(tmp_path)
    assert first.summary.accounts_partial == 1
    RecordingEvaluator.seen = []

    # The permission is fixed between runs.
    monkeypatch.setattr(
        audit_module.api_key_collector, "collect_bedrock_api_keys", lambda iam, now: ({}, [])
    )
    second = run(tmp_path, resume=True)

    assert set(RecordingEvaluator.seen) == {org["alpha"]}  # only the partial account was redone
    assert second.summary.accounts_partial == 0
    assert second.summary.accounts_scanned == 3


def test_e21_other_permission_errors_still_fail_the_account(org, tmp_path, monkeypatch):
    def deny(iam, now):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListAccessKeys")

    monkeypatch.setattr(audit_module, "collect_principals", deny_principals(deny))
    outcome = run(tmp_path)

    assert outcome.summary.accounts_failed == 3
    assert outcome.summary.accounts_partial == 0
    assert outcome.exit_code == EXIT_ALL_FAILED


def deny_principals(raiser):
    def collect_principals(iam, account_id, report, keys, now):
        raiser(iam, now)

    return collect_principals


def test_e20_limitation_notices_reach_the_terminal_and_findings_json(org, tmp_path):
    outcome = run(tmp_path)
    text = render_report(outcome.findings, outcome.summary, Config(output_dir=tmp_path / "out"))
    document = json.loads((tmp_path / "out" / "findings.json").read_text())

    for phrase in (
        "Service Control Policies or Resource Control Policies",
        "sts:AssumeRole is not followed",
    ):
        assert phrase in " ".join(text.split())
        assert any(phrase in notice for notice in document["limitations"])
    # The CSV stays one header row plus data rows, so it opens cleanly in a spreadsheet.
    first_line = (tmp_path / "out" / "findings.csv").read_text().splitlines()[0]
    assert first_line.startswith("tier,")


def report_generated_at(monkeypatch, when):
    """moto reports a fixed GeneratedTime from 2015, so pin the one the audit sees."""
    real = audit_module.fetch_credential_report_with_time

    def fetch(iam):
        rows, _ = real(iam)
        return rows, when

    monkeypatch.setattr(audit_module, "fetch_credential_report_with_time", fetch)


def test_e22_old_credential_report_is_flagged_with_its_generation_time(org, tmp_path, monkeypatch):
    generated = datetime.now(UTC) - timedelta(hours=3)
    report_generated_at(monkeypatch, generated)

    outcome = run(tmp_path)

    stale = [w for w in outcome.summary.warnings if "credential report was generated" in w]
    assert len(stale) == 3  # one per account
    assert all(f"{generated:%Y-%m-%d %H:%M} UTC" in w for w in stale)
    document = json.loads((tmp_path / "out" / "findings.json").read_text())
    assert {a["credential_report_generated_at"] for a in document["run"]["accounts"]} == {
        generated.isoformat()
    }
    text = render_report(outcome.findings, outcome.summary, Config(output_dir=tmp_path / "out"))
    assert f"{generated:%Y-%m-%d %H:%M} UTC" in text


def test_e22_fresh_credential_report_has_no_warning(org, tmp_path, monkeypatch):
    report_generated_at(monkeypatch, datetime.now(UTC) - timedelta(minutes=10))

    outcome = run(tmp_path)

    assert not [w for w in outcome.summary.warnings if "credential report" in w]
