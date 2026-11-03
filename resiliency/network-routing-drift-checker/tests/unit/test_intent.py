# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Intent schema + validator (tasks.md 2.1, requirements §7.2)."""

import textwrap

import pytest

from drift_core.intent import parse, resolve_isolation
from tests.fixtures import snapshots as fx

VALID = textwrap.dedent("""\
    version: 1
    tgw_isolation:
      prod:   [prod, shared]
      dev:    [dev, Shared]
      shared: [prod, dev, shared]
    dx_redundancy_pairs:
      - name: frankfurt-site-a
        members: [dxvif-0123abcd, dxvif-0456efgh]
    hybrid_paths:
      - prefix: 10.100.0.0/16
        exit_region: eu-central-1
      - prefix: 192.168.1.5/16
        preferred: dxvif-0123abcd
        backup: vpn-0abc1234
    regions:
      allow: []
      exclude: [ap-south-1]
    """)


def test_valid_file_builds_model():
    r = parse(VALID, "v1")
    assert r.status == "ok" and r.errors == [] and r.version_id == "v1"
    m = r.document
    assert m["tgw_isolation"] == {"prod": ["prod", "shared"], "dev": ["dev", "shared"],
                                  "shared": ["dev", "prod", "shared"]}
    assert m["dx_redundancy_pairs"] == [{"name": "frankfurt-site-a", "members": ["dxvif-0123abcd", "dxvif-0456efgh"]}]
    assert m["hybrid_paths"] == [{"prefix": "10.100.0.0/16", "exit_region": "eu-central-1"},
                                 {"prefix": "192.168.0.0/16", "preferred": "dxvif-0123abcd", "backup": "vpn-0abc1234"}]
    assert m["regions"] == {"allow": [], "exclude": ["ap-south-1"]}
    assert m["lines"]["tgw_isolation.dev"] == 4 and m["lines"]["hybrid_paths.192.168.0.0/16"] == 12
    assert r.manifest_entry()["model"] == m


def test_minimal_file():
    assert parse("version: 1\n").status == "ok"


@pytest.mark.parametrize("text,expected", [
    ("version: 1\ndx_redundency_pairs: []\n", "line 2: the intent file: unknown key 'dx_redundency_pairs'"),
    ("tgw_isolation: {}\n", "line 1: 'version: 1' is required"),
    ("version: 2\n", "line 1: version must be 1"),
    ("version: true\n", "line 1: version must be 1"),
    ("version: 1\nversion: 1\n", "line 2: the intent file: duplicate key 'version'"),
    ("version: 1\ndx_redundancy_pairs:\n  - name: a\n    members: [dxvif-01]\n",
     "line 4: dx_redundancy_pairs.a.members must list exactly two different VIF IDs"),
    ("version: 1\ndx_redundancy_pairs:\n  - name: a\n    members: [dxvif-01, dxvif-01]\n",
     "line 4: dx_redundancy_pairs.a.members must list exactly two different VIF IDs"),
    ("version: 1\ndx_redundancy_pairs:\n  - name: a\n    members: [dxvif-01, vpn-02]\n",
     "line 4: dx_redundancy_pairs.a.members: 'vpn-02' is not a VIF ID (dxvif-...)"),
    ("version: 1\ndx_redundancy_pairs:\n  - members: [dxvif-01, dxvif-02]\n",
     "line 3: dx_redundancy_pairs entry: missing name"),
    ("version: 1\nhybrid_paths:\n  - prefix: 10.0.0.0/8\n",
     "line 3: hybrid_paths 10.0.0.0/8: set at least one of exit_region, preferred, backup"),
    ("version: 1\nhybrid_paths:\n  - prefix: ten\n    exit_region: eu-central-1\n",
     "line 3: hybrid_paths: 'ten' is not a CIDR, e.g. 10.0.0.0/16"),
    ("version: 1\nhybrid_paths:\n  - prefix: 10.0.0.0/8\n    exit_region: Frankfurt\n",
     "line 4: hybrid_paths 10.0.0.0/8: 'Frankfurt' is not a Region code"),
    ("version: 1\nhybrid_paths:\n  - prefix: 10.0.0.0/8\n    preferred: dxvif-1\n    backup: dxvif-1\n",
     "line 3: hybrid_paths 10.0.0.0/8: preferred and backup must differ"),
    ("version: 1\nhybrid_paths:\n  - {prefix: 10.0.0.0/8, backup: vpn-1}\n  - {prefix: 10.0.0.0/8, backup: vpn-2}\n",
     "line 4: hybrid_paths: prefix 10.0.0.0/8 is listed twice"),
    ("version: 1\nregions:\n  allow: [eu_central]\n",
     "line 3: regions.allow: 'eu_central' is not a Region code, e.g. eu-central-1"),
    ("version: 1\ntgw_isolation: [prod]\n", "line 2: tgw_isolation must be a mapping (key: value)"),
    ("version: 1\ntgw_isolation:\n  prod: shared\n", "line 3: tgw_isolation.prod must be a list, e.g. [a, b]"),
])
def test_schema_errors_carry_line_and_reason(text, expected):
    r = parse(text)
    assert r.status == "rejected" and any(e.startswith(expected) for e in r.errors), r.errors


def test_all_errors_reported_in_line_order():
    r = parse("version: 3\nfoo: 1\nregions:\n  allow: [x]\n")
    assert [e.split(":")[0] for e in r.errors] == ["line 1", "line 2", "line 4"]


@pytest.mark.parametrize("text", ["", "just text", "- a\n- b\n", "version: 1\n  bad: [\n",
                                  "!!python/object/apply:os.system ['echo hi']",
                                  "version: !!python/object/apply:os.system ['x']\n"])
def test_rejected_never_raises(text):
    r = parse(text)
    assert r.status == "rejected" and r.errors and r.errors[0].startswith("line ")


def test_resolve_isolation_against_tables():
    model = parse(VALID).document
    region = fx.region(route_tables=[fx.tgw_table("tgw-rtb-0prd", "prod"), fx.tgw_table("tgw-rtb-0dev", "dev"),
                                     fx.tgw_table("tgw-rtb-0shr", "Shared")])
    assert resolve_isolation(model, {"eu-central-1": region}, "Environment") == []
    model["tgw_isolation"]["tgw-rtb-0prd"] = ["tgw-rtb-0dev", "staging"]
    model["lines"]["tgw_isolation.tgw-rtb-0prd"] = 9
    errors = resolve_isolation(model, {"eu-central-1": region}, "Environment")
    assert errors == ["line 9: tgw_isolation.tgw-rtb-0prd: 'staging' matches no route table ID or Environment "
                      "tag value"]
    nothing = resolve_isolation(parse(VALID).document, {}, "Environment")
    assert nothing[0] == "line 3: tgw_isolation.prod: 'prod' matches no route table ID or Environment tag value"
    assert "line 4: tgw_isolation: 'dev' matches no route table ID or Environment tag value" in nothing
    assert "(allowed: version, tgw_isolation" in parse("version: 1\nfoo: 1\n").errors[0]
