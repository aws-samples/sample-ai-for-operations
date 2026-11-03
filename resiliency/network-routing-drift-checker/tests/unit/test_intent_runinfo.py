# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Intent-file stub (tasks.md 1.25) and run identity / overrides (tasks.md 1.24)."""

import pytest

from drift_core.intent import parse
from drift_core.run_info import InputError, RunInfo, default_lookback


def test_intent_ok_and_rejected_forms():
    assert parse("version: 1\n", "v1").status == "ok"
    bad = parse("version: 1\n  oops: [\n", "v2")
    assert bad.status == "rejected" and bad.errors[0].startswith("line ") and bad.version_id == "v2"
    scalar = parse("just a string")
    assert scalar.status == "rejected" and "must be a mapping" in scalar.errors[0]
    assert parse("").status == "rejected"
    entry = parse("version: 1").manifest_entry()
    assert entry["status"] == "ok" and entry["errors"] == [] and entry["model"]["version"] == 1


def test_intent_safe_load_rejects_python_tags():
    assert parse("!!python/object/apply:os.system ['echo hi']").status == "rejected"


def ev(**inp):
    return {"execution_name": "abc", "started_at": "2026-05-12T05:00:00.123Z", "input": inp}


def test_scheduled_run_is_full_scope_and_id_is_deterministic():
    a, b = RunInfo.from_event(ev()), RunInfo.from_event(ev())
    assert a.scope == "full" and a.run_id == b.run_id and a.run_id.startswith("2026-05-12T05:00:00Z-")
    assert a.date == "2026-05-12" and a.override_regions is None


def test_overrides_make_partial_scope():
    r = RunInfo.from_event(ev(regions=["eu-west-1", "eu-central-1", "eu-west-1"]))
    assert r.scope == "partial" and r.override_regions == ("eu-central-1", "eu-west-1")
    lb = RunInfo.from_event(ev(lookback_from="2026-05-01T00:00:00+02:00"))
    assert lb.scope == "partial" and lb.override_lookback_from == "2026-04-30T22:00:00Z"


@pytest.mark.parametrize("event", [
    "nope", {"started_at": "2026-05-12T05:00:00Z"}, {"execution_name": "x", "started_at": "yesterday"},
    {"execution_name": "x", "started_at": "2026-05-12T05:00:00"}, ev(regions=[]), ev(regions=["EU_CENTRAL"]),
    ev(extra=1), {"execution_name": "x", "started_at": "2026-05-12T05:00:00Z", "input": [1]},
])
def test_bad_input_rejected(event):
    with pytest.raises(InputError):
        RunInfo.from_event(event)


def test_default_lookback():
    assert default_lookback("2026-05-12T05:00:00Z") == "2026-05-11T05:00:00Z"
