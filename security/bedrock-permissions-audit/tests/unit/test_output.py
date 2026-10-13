# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import csv
import io
import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.models import Account, AccountResult, Tier
from bedrock_permissions_audit.output.csv_writer import render_csv, write_csv
from bedrock_permissions_audit.output.files import write_private
from bedrock_permissions_audit.output.json_writer import render_json
from bedrock_permissions_audit.output.remediation import (
    FILE_DENY_API_KEYS,
    FILE_DENY_USERS,
    FILE_RESTRICT,
    MARKER,
    render_all,
    write_remediation,
)
from bedrock_permissions_audit.output.rows import CSV_COLUMNS, csv_safe
from bedrock_permissions_audit.output.terminal import render_report
from bedrock_permissions_audit.scoring import score
from bedrock_permissions_audit.summary import SCP_NOTICE, collect_findings, summarize

from .factories import ADMIN, INVOKE, KEY_ID, allowed, credential, finding

CONFIG = Config()
T0 = datetime(2026, 6, 1, tzinfo=UTC)


def scored(config=CONFIG, **overrides):
    return score(finding(**overrides), config)


def sample():
    return [
        scored(admin_policies=(ADMIN,), principal_name="admin"),
        scored(credential=credential(unused_days=300, age_days=400), principal_name="old"),
        scored(grant="scoped", principal_name="scoped"),
    ]


def make_summary(findings=None, config=CONFIG, failed=()):
    findings = sample() if findings is None else findings
    ok = AccountResult(
        Account("123456789012", "workloads"),
        "ok",
        findings=tuple(findings),
        principals_evaluated=len(findings),
    )
    results = [ok, *failed]
    return summarize("org", T0, T0, results, config), results


class TestCsv:
    def parse(self, text):
        return list(csv.DictReader(io.StringIO(text)))

    def test_header_and_one_row_per_finding(self):
        text = render_csv(sample(), CONFIG)
        rows = self.parse(text)

        assert text.splitlines()[0].split(",") == list(CSV_COLUMNS)
        assert [r["principal"] for r in rows] == ["admin", "old", "scoped"]
        assert rows[0]["tier"] == "Critical"
        assert rows[0]["admin_policies"] == ADMIN

    def test_key_ids_are_masked_by_default_and_full_with_unmask(self):
        assert KEY_ID not in render_csv(sample(), CONFIG)
        assert "...MPLE" in render_csv(sample(), CONFIG)
        assert KEY_ID in render_csv(sample(), Config(unmask=True))

    @pytest.mark.parametrize("name", ['=HYPERLINK("http://x","y")', "+1+1", "-2+3", "@SUM(A1)"])
    def test_spreadsheet_formulas_are_neutralised(self, name):
        rows = self.parse(render_csv([scored(principal_name=name)], CONFIG))
        assert rows[0]["principal"].startswith("'")
        assert rows[0]["principal"][1:] == name

    def test_ordinary_values_are_not_altered(self):
        assert csv_safe("alice") == "alice"
        assert csv_safe("arn:aws:iam::1:user/a-b") == "arn:aws:iam::1:user/a-b"

    def test_commas_quotes_and_newlines_round_trip(self):
        rows = self.parse(render_csv([scored(principal_name='a,"b"\nc')], CONFIG))
        assert rows[0]["principal"] == 'a,"b"c'  # newline is a control character and is stripped

    def test_never_used_and_unknown_last_use_are_distinguished(self):
        never = scored(credential=credential(unused_days=None, last_used=None))
        unknown = scored(
            credential=credential(
                kind="bedrock_api_key", unused_days=None, last_used=None, last_used_known=False
            )
        )
        rows = self.parse(render_csv([never, unknown], CONFIG))
        assert [r["last_used_days"] for r in rows] == ["never", "unknown"]

    def test_file_is_owner_only(self, tmp_path):
        path = tmp_path / "out" / "findings.csv"
        write_csv(path, sample(), CONFIG)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def inactive_admin(**overrides):
    values = {
        "admin_policies": (ADMIN,),
        "mfa_active": False,
        "credential": credential(active=False, age_days=390, unused_days=350),
        "principal_name": "legacy",
    }
    values.update(overrides)
    return scored(**values)


class TestReactivationFields:
    def test_csv_has_the_column_last_and_fills_it(self):
        rows = list(csv.DictReader(io.StringIO(render_csv([inactive_admin(), scored()], CONFIG))))

        assert CSV_COLUMNS[-1] == "if_reactivated_tier"
        assert list(rows[0])[-1] == "if_reactivated_tier"
        assert (rows[0]["tier"], rows[0]["if_reactivated_tier"]) == ("Low", "Critical")
        assert (rows[1]["tier"], rows[1]["if_reactivated_tier"]) == ("Medium", "")

    def test_csv_would_be_high(self):
        row = inactive_admin(admin_policies=())
        assert row.if_reactivated_tier is Tier.HIGH
        parsed = list(csv.DictReader(io.StringIO(render_csv([row], CONFIG))))
        assert parsed[0]["if_reactivated_tier"] == "High"

    def test_json_field_is_upper_case_name_or_null_and_schema_is_unchanged(self):
        findings = [
            inactive_admin(),
            inactive_admin(admin_policies=(), principal_name="h"),
            scored(),
        ]
        summary, _ = make_summary(findings)

        document = json.loads(render_json(findings, summary, CONFIG))

        assert document["schema"] == 1
        assert [f["if_reactivated_tier"] for f in document["findings"]] == [
            "CRITICAL",
            "HIGH",
            None,
        ]

    def test_json_and_csv_agree_on_the_field(self):
        findings = [inactive_admin(), scored()]
        summary, _ = make_summary(findings)
        document = json.loads(render_json(findings, summary, CONFIG))
        rows = list(csv.DictReader(io.StringIO(render_csv(findings, CONFIG))))

        assert [(f["if_reactivated_tier"] or "").title() for f in document["findings"]] == [
            r["if_reactivated_tier"] for r in rows
        ]

    def test_terminal_shows_the_row_the_action_and_the_would_be_tier(self):
        findings = [inactive_admin()]
        summary, results = make_summary(findings)

        text = render_report(collect_findings(results, CONFIG), summary, CONFIG, Path("out"))

        row = next(line for line in text.splitlines() if line.startswith("Low"))
        assert "legacy" in row
        assert "Delete inactive access key ...MPLE on legacy." in text
        assert "why: If re-enabled it would rate Critical:" in text
        assert "No findings to report." not in text
        assert "Findings: Critical 0  High 0  Medium 0  Low 1  Info 0" in text


class TestJson:
    def document(self, config=CONFIG, findings=None):
        findings = sample() if findings is None else findings
        summary, _ = make_summary(findings, config)
        return json.loads(render_json(findings, summary, config))

    def test_schema_summary_and_limitations(self):
        document = self.document()
        assert document["schema"] == 1
        assert document["run"]["accounts_scanned"] == 1
        assert SCP_NOTICE in document["limitations"]

    def test_same_findings_as_csv(self):
        findings = sample()
        document = self.document(findings=findings)
        csv_rows = list(csv.DictReader(io.StringIO(render_csv(findings, CONFIG))))
        assert [f["principal_name"] for f in document["findings"]] == [
            r["principal"] for r in csv_rows
        ]
        assert [f["tier"] for f in document["findings"]] == [r["tier"].upper() for r in csv_rows]

    def test_keys_masked_unless_unmask(self):
        assert KEY_ID not in json.dumps(self.document())
        assert KEY_ID in json.dumps(self.document(Config(unmask=True)))

    def test_per_action_decisions_and_policy_names_are_included(self):
        item = self.document()["findings"][0]
        assert item["results"][0]["action"] == INVOKE
        assert item["results"][0]["decision"] == "allowed"
        assert item["granting_policies"] == ["Policy (IAM Policy)"]
        assert INVOKE in item["bedrock_actions_allowed"]

    def test_empty_run_is_valid(self):
        document = self.document(findings=[])
        assert document["findings"] == []


class TestTerminal:
    def render(self, findings=None, color=False, config=CONFIG, **kwargs):
        findings = sample() if findings is None else findings
        summary, _ = make_summary(findings, config, **kwargs)
        return render_report(findings, summary, config, Path("out"), color)

    def test_shows_tiers_recommendation_and_summary(self):
        text = self.render()
        assert "Critical" in text and "High" in text and "Low" in text
        assert "-> " in text
        assert "Accounts scanned: 1" in text
        assert "Findings: Critical 1  High 1  Medium 0  Low 1  Info 0" in text
        assert SCP_NOTICE[:40] in text
        assert "Output: out" in text

    def test_no_colour_codes_by_default(self):
        assert "\x1b[" not in self.render()

    def test_colour_when_requested(self):
        text = self.render(color=True)
        assert "\x1b[" in text and "\x1b[0m" in text

    def test_key_ids_are_masked(self):
        assert KEY_ID not in self.render()

    def test_escape_sequences_in_names_cannot_reach_the_terminal(self):
        nasty = scored(principal_name="evil\x1b[2J\x1b]0;pwned\x07name")
        text = self.render([nasty])
        assert "\x1b" not in text
        assert "\x07" not in text
        assert "evil" in text

    def test_long_names_are_truncated_in_the_table_row(self):
        text = self.render([scored(principal_name="x" * 64)])  # 64 is the IAM maximum
        row = next(line for line in text.splitlines() if line.startswith("Medium"))
        assert "x" * 64 not in row
        assert "~" in row

    def test_no_findings_message(self):
        assert "No findings to report." in self.render([])

    def test_failed_accounts_are_listed_with_the_reason(self):
        failed = AccountResult(
            Account("222222222222", "broken"),
            "failed",
            reason="AssumeRoleError: Cannot assume role: AccessDenied",
        )
        text = self.render(failed=[failed])
        assert "failed: 1" in text
        assert "222222222222 (broken): AssumeRoleError" in text

    def test_hidden_info_is_counted(self):
        info = scored(results=allowed("s3:GetObject"), grant="none", principal_name="s3")
        findings = [*sample(), info]
        summary, results = make_summary(findings)
        visible = collect_findings(results, CONFIG)
        text = render_report(visible, summary, CONFIG)
        assert "1 Info findings hidden" in text
        assert "s3" not in text.split("Summary")[0]

    def test_unknown_rows_are_shown_and_say_so(self):
        unknown = scored(grant="unknown", results=(), principal_name="mystery")
        text = self.render([unknown])
        assert "mystery" in text
        assert "manually" in text


class TestSummary:
    def test_counts_are_computed_from_the_findings(self):
        summary, _ = make_summary()
        assert summary.tier_counts == {"Critical": 1, "High": 1, "Medium": 0, "Low": 1, "Info": 0}
        assert summary.principals_evaluated == 3

    def test_info_is_counted_only_with_all(self):
        info = scored(results=allowed("s3:GetObject"), grant="none")
        hidden, _ = make_summary([info])
        shown, _ = make_summary([info], Config(show_all=True))
        assert (hidden.tier_counts["Info"], hidden.hidden_info) == (0, 1)
        assert (shown.tier_counts["Info"], shown.hidden_info) == (1, 0)

    def test_failed_accounts_are_reported_with_reason(self):
        failed = AccountResult(Account("222222222222"), "failed", reason="boom")
        summary, _ = make_summary(failed=[failed])
        assert summary.accounts_failed == 1
        assert summary.failed_accounts == [
            {"account_id": "222222222222", "name": "", "reason": "boom"}
        ]

    def test_findings_from_failed_accounts_are_excluded(self):
        bad = AccountResult(Account("222222222222"), "failed", reason="x", findings=tuple(sample()))
        _, results = make_summary(failed=[bad])
        assert len(collect_findings(results, CONFIG)) == 3

    def test_warnings_carry_their_account(self):
        result = AccountResult(Account("123456789012"), "ok", warnings=("check this",))
        summary = summarize("org", T0, T0, [result], CONFIG)
        assert summary.warnings == ["123456789012: check this"]

    def test_scp_limitation_is_always_present(self):
        summary, _ = make_summary([])
        assert SCP_NOTICE in summary.notices


class TestRemediation:
    def test_always_writes_the_user_scp_and_api_key_policy(self):
        names = set(render_all(CONFIG))
        assert names == {FILE_DENY_USERS, FILE_DENY_API_KEYS}

    def test_restrict_policy_needs_regions_or_models(self):
        assert FILE_RESTRICT not in render_all(CONFIG)
        assert FILE_RESTRICT in render_all(Config(bedrock_regions=("eu-west-1",)))
        assert FILE_RESTRICT in render_all(Config(approved_models=("amazon.nova-lite-v1:0",)))

    def test_every_statement_carries_the_review_marker(self):
        config = Config(bedrock_regions=("eu-west-1",), approved_models=("amazon.nova-lite-v1:0",))
        for name, document in render_all(config).items():
            assert document["Statement"], name
            for statement in document["Statement"]:
                assert statement["Sid"].startswith(MARKER), (name, statement["Sid"])

    def test_documents_only_use_keys_aws_accepts(self):
        config = Config(bedrock_regions=("eu-west-1",), approved_models=("amazon.nova-lite-v1:0",))
        for document in render_all(config).values():
            assert set(document) == {"Version", "Statement"}

    def test_user_scp_denies_users_and_root_but_not_roles(self):
        statement = render_all(CONFIG)[FILE_DENY_USERS]["Statement"][0]
        assert statement["Effect"] == "Deny"
        assert statement["Condition"]["StringEquals"]["aws:PrincipalType"] == ["User", "Account"]
        assert "bedrock:InvokeModel" in statement["Action"]
        assert "ArnNotLike" not in statement["Condition"]

    def test_exception_principals_are_rendered(self):
        config = Config(scp_exception_principals=("arn:aws:iam::*:user/ci-*",))
        condition = render_all(config)[FILE_DENY_USERS]["Statement"][0]["Condition"]
        assert condition["ArnNotLike"] == {"aws:PrincipalArn": ["arn:aws:iam::*:user/ci-*"]}

    def test_model_allowlist_covers_foundation_models_and_inference_profiles(self):
        config = Config(approved_models=("anthropic.claude-3-haiku-20240307-v1:0",))
        statement = render_all(config)[FILE_RESTRICT]["Statement"][0]
        assert statement["NotResource"] == [
            "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
            "arn:aws:bedrock:*:*:inference-profile/*.anthropic.claude-3-haiku-20240307-v1:0",
        ]
        assert not any("CallWithBearerToken" in a for a in statement["Action"])

    def test_region_policy_uses_requested_region(self):
        config = Config(bedrock_regions=("eu-west-1", "eu-central-1"))
        statement = render_all(config)[FILE_RESTRICT]["Statement"][0]
        assert statement["Condition"]["StringNotEquals"]["aws:RequestedRegion"] == [
            "eu-west-1",
            "eu-central-1",
        ]

    def test_api_key_policy_denies_both_endpoints_and_creation(self):
        statements = render_all(CONFIG)[FILE_DENY_API_KEYS]["Statement"]
        assert statements[0]["Action"] == [
            "bedrock:CallWithBearerToken",
            "bedrock-mantle:CallWithBearerToken",
        ]
        assert statements[1]["Action"] == "iam:CreateServiceSpecificCredential"
        assert statements[1]["Condition"]["StringEquals"] == {
            "iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com"
        }

    def test_files_written_are_valid_json_with_a_readme(self, tmp_path):
        written = write_remediation(tmp_path / "remediation", CONFIG)

        assert "README.txt" in written
        for name in written:
            path = tmp_path / "remediation" / name
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            if name.endswith(".json"):
                json.loads(path.read_text())
        readme = (tmp_path / "remediation" / "README.txt").read_text()
        assert "REVIEW BEFORE APPLYING" in readme
        assert FILE_RESTRICT in readme  # explains why it was not written

    def test_scp_size_limit_is_respected_for_a_large_allowlist(self):
        models = tuple(f"vendor.model-{i}-v1:0" for i in range(40))
        document = render_all(Config(approved_models=models))[FILE_RESTRICT]
        assert len(json.dumps(document, separators=(",", ":"))) < 5120


def test_write_private_replaces_atomically_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "f.txt"
    write_private(path, "one")
    write_private(path, "two")
    assert path.read_text() == "two"
    assert [p.name for p in tmp_path.iterdir()] == ["f.txt"]
    assert Tier.CRITICAL < Tier.INFO


class TestTerminalReasons:
    """E24: every reason reaches the terminal, and an inactive key's inner reasons sit under the
    'would rate' line."""

    def lines(self, findings, config=CONFIG):
        summary, results = make_summary(findings, config)
        text = render_report(collect_findings(results, config), summary, config, Path("out"))
        return text.splitlines()

    def test_inactive_admin_key_shows_the_evidence_for_its_would_be_tier(self):
        lines = self.lines([inactive_admin()])

        start = next(
            i for i, line in enumerate(lines) if "If re-enabled it would rate Critical:" in line
        )
        nested = lines[start + 1 : start + 3]

        assert "why: The key is inactive but its secret works again" in lines[start - 1]
        assert nested[0].endswith("- Can invoke Amazon Bedrock models.")
        assert nested[1].endswith("- Holds an admin-class policy: AdministratorAccess.")

    def test_inner_reasons_are_indented_deeper_than_the_why_lines(self):
        lines = self.lines([inactive_admin()])

        why = next(line for line in lines if "why: If re-enabled" in line)
        inner = next(line for line in lines if "Holds an admin-class policy" in line)

        assert len(inner) - len(inner.lstrip()) > len(why) - len(why.lstrip())
        assert "why:" not in inner

    def test_no_reason_is_dropped_however_many_there_are(self):
        escalation = CONFIG.escalation_actions[0]
        row = inactive_admin(results=allowed(INVOKE, escalation))
        assert len(row.tier_reasons) > 4

        text = "\n".join(self.lines([row]))

        for reason in row.tier_reasons:
            assert reason in text

    def test_an_active_finding_with_many_reasons_keeps_them_all_flat(self):
        row = scored(
            admin_policies=(ADMIN,),
            mfa_active=False,
            results=allowed(INVOKE, CONFIG.escalation_actions[0], *CONFIG.canary_actions),
        )
        assert len(row.tier_reasons) == 4

        lines = self.lines([row])

        assert sum("why:" in line for line in lines) == len(row.tier_reasons)
        table = lines[: lines.index("Summary")]  # the limitations below it are bulleted
        assert not any(line.lstrip().startswith("- ") for line in table)


def no_access(name, **credential_overrides):
    """An Info finding: it holds no Amazon Bedrock permission."""
    return scored(
        principal_name=name,
        credential=credential(**credential_overrides),
        results=allowed("s3:GetObject"),
        grant="none",
    )


class TestHiddenInfoByReason:
    """E25: hidden Info findings are counted by cause."""

    def mixed(self):
        return [
            no_access("s3only"),
            no_access("deactivated", active=False),
            no_access("lapsed", kind="bedrock_api_key", active=False, expired=True),
        ]

    def render(self, findings, config=CONFIG):
        summary, results = make_summary(findings, config)
        return summary, render_report(collect_findings(results, config), summary, config)

    def test_summary_line_counts_each_cause_separately(self):
        _, text = self.render(self.mixed())

        assert (
            "3 Info findings hidden (1 cannot invoke Amazon Bedrock, "
            "2 expired or inactive credentials); use --all to show them."
        ) in text

    def test_a_cause_with_no_findings_is_not_listed(self):
        _, text = self.render([no_access("a"), no_access("b")])

        assert "2 Info findings hidden (2 cannot invoke Amazon Bedrock); use --all" in text
        assert "inactive credentials" not in text

        _, text = self.render([no_access("a", active=False)])
        assert "1 Info findings hidden (1 expired or inactive credentials); use --all" in text
        assert "cannot invoke Amazon Bedrock)" not in text

    def test_counts_sum_to_the_hidden_total_and_reach_the_json(self):
        findings = self.mixed()
        summary, _ = make_summary(findings)

        document = json.loads(render_json(collect_findings([], CONFIG), summary, CONFIG))

        assert document["schema"] == 1
        assert document["run"]["hidden_info_by_reason"] == {
            "cannot_invoke": 1,
            "inactive_or_expired": 2,
        }
        assert (
            sum(document["run"]["hidden_info_by_reason"].values()) == document["run"]["hidden_info"]
        )

    def test_nothing_is_hidden_with_all_and_the_line_disappears(self):
        config = Config(show_all=True)
        summary, text = self.render(self.mixed(), config)

        assert summary.hidden_info == 0
        assert summary.hidden_info_by_reason == {"cannot_invoke": 0, "inactive_or_expired": 0}
        assert "hidden" not in text

    def test_an_inactive_key_that_would_rate_high_is_shown_not_counted_as_hidden(self):
        summary, _ = make_summary([inactive_admin(), no_access("s3only")])

        assert summary.hidden_info_by_reason == {"cannot_invoke": 1, "inactive_or_expired": 0}

    def test_hidden_reason_covers_a_principal_with_no_credential_and_an_inactive_root(self):
        from bedrock_permissions_audit.scoring.ordering import hidden_reason

        no_credential = scored(credential=None, results=(), grant="none")
        inactive_root = scored(is_root=True, credential=credential(active=False))

        assert hidden_reason(no_credential) == "inactive_or_expired"
        assert hidden_reason(inactive_root) == "inactive_or_expired"
        assert hidden_reason(no_access("s3only")) == "cannot_invoke"
