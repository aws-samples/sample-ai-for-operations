# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Deterministic finding IDs (requirements §14.1, design D§5)."""

import pytest

from drift_core.finding import Finding, canonical_json, canonical_prefix, dedupe, finding_id


def _leak(**over):
    base = dict(
        check="check2",
        kind="tgw-prefix-leak",
        severity="drift",
        region="eu-central-1",
        identity=("tgw-rtb-0aaa", "10.100.5.0/24", "tgw-attach-0bbb"),
        expected={"allowed": ["prod", "shared"]},
        observed={"source_env": "dev"},
    )
    base.update(over)
    return Finding(**base)


def test_id_is_stable_and_prefixed():
    assert _leak().finding_id == _leak().finding_id
    assert _leak().finding_id.startswith("f-")
    assert len(_leak().finding_id) == 22


def test_id_independent_of_identity_order_and_case():
    a = _leak(identity=("tgw-rtb-0aaa", "10.100.5.0/24", "tgw-attach-0bbb"))
    b = _leak(identity=("TGW-ATTACH-0BBB", "tgw-rtb-0aaa", " 10.100.5.0/24 "))
    assert a.finding_id == b.finding_id


def test_id_independent_of_observed_and_context():
    a = _leak(observed={"count": 1}, context={"ts": "2026-05-12T05:00:00Z"})
    b = _leak(observed={"count": 99}, context={"ts": "2026-05-13T05:00:00Z"})
    assert a.finding_id == b.finding_id
    assert a.payload_hash != b.payload_hash


def test_payload_hash_independent_of_key_and_list_order():
    a = _leak(expected={"allowed": ["prod", "shared"], "x": 1})
    b = _leak(expected={"x": 1, "allowed": ["shared", "prod"]})
    assert a.payload_hash == b.payload_hash


def test_different_drift_different_id():
    assert _leak().finding_id != _leak(identity=("tgw-rtb-0aaa", "10.100.6.0/24", "tgw-attach-0bbb")).finding_id
    assert _leak().finding_id != _leak(region="eu-west-1").finding_id
    assert _leak().finding_id != _leak(kind="cloudwan-prefix-leak").finding_id


def test_module_function_matches_property():
    f = _leak()
    assert finding_id(f.kind, f.region, list(f.identity)) == f.finding_id


def test_roundtrip_dict():
    f = _leak()
    g = Finding.from_dict(f.to_dict())
    assert g == f and g.finding_id == f.finding_id


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("10.0.1.5/16", "10.0.0.0/16"),
        ("10.100.0.0/16", "10.100.0.0/16"),
        ("2001:DB8::/32", "2001:db8::/32"),
        ("pl-0ABC123", "pl-0abc123"),
    ],
)
def test_canonical_prefix(raw, expected):
    assert canonical_prefix(raw) == expected


def test_canonical_json_sorted():
    assert canonical_json({"b": [2, 1], "a": 1}) == '{"a":1,"b":[1,2]}'


@pytest.mark.parametrize(
    "over",
    [{"check": "check9"}, {"severity": "fatal"}, {"kind": ""}, {"identity": ()}],
)
def test_validation(over):
    with pytest.raises(ValueError):
        _leak(**over)


def test_dedupe_first_wins_and_stable_order():
    a = _leak(message="first")
    b = _leak(message="second")
    c = _leak(identity=("x",))
    out = dedupe([c, a, b])
    assert len(out) == 2
    assert next(f for f in out if f.finding_id == a.finding_id).message == "first"
    assert dedupe([c, a]) == dedupe([a, c])
