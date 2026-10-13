# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import csv
import io
from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError

from bedrock_permissions_audit.collectors.credential_report import (
    ROOT_USER,
    CredentialReportTimeout,
    fetch_credential_report,
    fetch_credential_report_with_time,
    parse_report,
)

HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
    "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
    "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,"
    "cert_1_last_rotated,cert_2_active,cert_2_last_rotated"
).split(",")

BLANK = {name: "N/A" for name in HEADER}


def build_csv(*rows: dict[str, str]) -> bytes:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=HEADER)
    writer.writeheader()
    for row in rows:
        writer.writerow({**BLANK, **row})
    return out.getvalue().encode()


ROOT_WITH_KEY = {
    "user": ROOT_USER,
    "arn": "arn:aws:iam::123456789012:root",
    "mfa_active": "false",
    "access_key_1_active": "true",
    "access_key_1_last_rotated": "2021-05-04T10:00:00+00:00",
    "access_key_1_last_used_date": "2021-05-05T00:00:00+00:00",
    "access_key_1_last_used_region": "us-east-1",
    "access_key_2_active": "false",
}
ALICE = {
    "user": "alice",
    "arn": "arn:aws:iam::123456789012:user/alice",
    "mfa_active": "true",
    "access_key_1_active": "true",
    "access_key_1_last_rotated": "2025-01-01T00:00:00+00:00",
    "access_key_1_last_used_date": "N/A",
    "access_key_1_last_used_region": "N/A",
    "access_key_2_active": "false",
}


def test_parse_reads_users_mfa_and_key_slots():
    rows = parse_report(build_csv(ROOT_WITH_KEY, ALICE))

    assert set(rows) == {ROOT_USER, "alice"}
    alice = rows["alice"]
    assert alice.mfa_active is True
    assert alice.arn.endswith("user/alice")
    first, second = alice.keys
    assert first.exists and first.active
    assert first.last_rotated == datetime(2025, 1, 1, tzinfo=UTC)
    assert first.last_used is None  # "N/A" means never used
    assert first.last_used_region is None
    assert not second.exists  # an empty slot has no rotation date


def test_parse_root_key_with_usage():
    key = parse_report(build_csv(ROOT_WITH_KEY))[ROOT_USER].keys[0]
    assert key.last_used == datetime(2021, 5, 5, tzinfo=UTC)
    assert key.last_used_region == "us-east-1"


@pytest.mark.parametrize("placeholder", ["N/A", "not_supported", "no_information", ""])
def test_all_placeholder_values_become_none(placeholder):
    row = {**ALICE, "access_key_1_last_used_date": placeholder}
    assert parse_report(build_csv(row))["alice"].keys[0].last_used is None


def test_parse_accepts_str_and_bytes():
    data = build_csv(ALICE)
    assert parse_report(data).keys() == parse_report(data.decode()).keys()


class FakeIam:
    """Scripted responses for generate/get calls, so no sleeping or network is involved."""

    def __init__(self, get_script):
        self.get_script = list(get_script)
        self.generated = datetime(2026, 6, 1, 8, 30, tzinfo=UTC)
        self.generate_calls = 0

    def generate_credential_report(self):
        self.generate_calls += 1
        return {"State": "STARTED"}

    def get_credential_report(self):
        item = self.get_script.pop(0)
        if isinstance(item, str):
            raise ClientError({"Error": {"Code": item, "Message": item}}, "GetCredentialReport")
        return {"Content": item, "GeneratedTime": self.generated}


class Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_polls_until_the_report_is_ready():
    clock = Clock()
    iam = FakeIam(["ReportInProgress", "ReportInProgress", build_csv(ALICE)])

    rows = fetch_credential_report(iam, 60, 2, clock.sleep, clock.monotonic)

    assert "alice" in rows
    assert clock.slept == [2, 2]
    assert iam.generate_calls == 1


def test_regenerates_when_no_report_is_present():
    clock = Clock()
    iam = FakeIam(["ReportNotPresent", build_csv(ALICE)])

    fetch_credential_report(iam, 60, 2, clock.sleep, clock.monotonic)

    assert iam.generate_calls == 2


def test_times_out_with_a_clear_error():
    clock = Clock()
    iam = FakeIam(["ReportInProgress"] * 100)

    with pytest.raises(CredentialReportTimeout, match="not ready after 10 seconds"):
        fetch_credential_report(iam, 10, 2, clock.sleep, clock.monotonic)


def test_other_errors_are_not_swallowed():
    iam = FakeIam(["AccessDenied"])
    with pytest.raises(ClientError):
        fetch_credential_report(iam, 10, 2, lambda s: None, lambda: 0.0)


def test_returns_when_iam_generated_the_report():
    clock = Clock()
    iam = FakeIam([build_csv(ALICE)])

    rows, generated = fetch_credential_report_with_time(iam, 60, 2, clock.sleep, clock.monotonic)

    assert "alice" in rows
    assert generated == datetime(2026, 6, 1, 8, 30, tzinfo=UTC)


def test_generation_time_is_none_when_iam_omits_it():
    iam = FakeIam([build_csv(ALICE)])
    iam.generated = None

    _, generated = fetch_credential_report_with_time(iam, 60, 2, lambda s: None, lambda: 0.0)

    assert generated is None
