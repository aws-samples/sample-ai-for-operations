# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Handlers end to end with in-memory fakes, driven by the REAL recorded lab responses.

init -> collect-cloudwan -> collect-region (x3) -> evaluate -> diff -> report, twice, to
prove NEW then KNOWN, the not-evaluated path, the intent paths and the marker read.
"""

import io
import json
import pathlib

import pytest
from botocore.exceptions import ClientError

from handlers import aws_clients, collect, init_run, pipeline

RECORDED = json.loads((pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "recorded"
                       / "raw_responses.json").read_text())
BUCKET, TABLE = "drift-bucket", "drift-table"


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, ContentType=None):  # noqa: N803
        self.objects[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.encode()

    def get_object(self, Bucket, Key):  # noqa: N803
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)]), "VersionId": "v-test"}

    def json(self, key):
        return json.loads(self.objects[(BUCKET, key)])


class FakeTable:
    def __init__(self):
        self.items = {}

    def query(self, IndexName, KeyConditionExpression):  # noqa: N803
        return {"Items": [i for i in self.items.values() if i.get("status") == "open"]}

    def batch_writer(self, overwrite_by_pkeys=None):
        table = self

        class _W:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def put_item(self, Item):  # noqa: N803
                table.items[Item["pk"]] = Item

        return _W()

    def get_item(self, Key):  # noqa: N803
        return {"Item": self.items[Key["pk"]]} if Key["pk"] in self.items else {}

    def put_item(self, Item):  # noqa: N803
        self.items[Item["pk"]] = Item


class Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_):
        return iter(self._pages)


class FakeEC2:
    def __init__(self, region, fail=False):
        self.region, self.fail = region, fail
        self.raw = RECORDED["regions"].get(region, {}).get("tgw") or {
            "transit_gateways": [], "route_tables": [], "attachments": [], "routes": {}}

    def _check(self):
        if self.fail:
            raise ClientError({"Error": {"Code": "ThrottlingException"}}, "Describe")

    def describe_regions(self, Filters):  # noqa: N803
        return {"Regions": [{"RegionName": r} for r in ("eu-central-1", "eu-west-1", "us-east-1", "ap-south-1")]}

    def describe_transit_gateways(self, MaxResults=None):  # noqa: N803
        self._check()
        return {"TransitGateways": self.raw["transit_gateways"]}

    def get_paginator(self, op):
        self._check()
        key = {"describe_transit_gateways": ("TransitGateways", "transit_gateways"),
               "describe_transit_gateway_route_tables": ("TransitGatewayRouteTables", "route_tables"),
               "describe_transit_gateway_attachments": ("TransitGatewayAttachments", "attachments")}[op]
        return Paginator([{key[0]: self.raw[key[1]]}])

    def search_transit_gateway_routes(self, TransitGatewayRouteTableId, **_):  # noqa: N803
        return {"Routes": self.raw["routes"][TransitGatewayRouteTableId]["routes"]}

    def describe_vpn_connections(self):
        self._check()
        return {"VpnConnections": []}


class FakeDX:
    def __init__(self, region):
        self.region = region

    def get_paginator(self, op):
        gw = RECORDED["dx_gateways"]
        if op == "describe_direct_connect_gateways":
            return Paginator([{"directConnectGateways": gw["gateways"]}])
        return Paginator([{"directConnectGatewayAssociations": []}])

    def describe_virtual_interfaces(self):
        return {"virtualInterfaces": RECORDED["regions"].get(self.region, {}).get("dx", {}).get(
            "virtual_interfaces", [])}


class FakeNM:
    def __init__(self):
        self.raw = RECORDED["cloudwan"]

    def get_paginator(self, op):
        if op == "list_core_networks":
            return Paginator([{"CoreNetworks": [{"CoreNetworkId": self.raw["core_network"]["CoreNetworkId"],
                                                 "State": "AVAILABLE"}]}])
        return Paginator([{"Attachments": self.raw["attachments"]}])

    def get_core_network(self, CoreNetworkId):  # noqa: N803
        return {"CoreNetwork": self.raw["core_network"]}

    def get_core_network_policy(self, CoreNetworkId, Alias):  # noqa: N803
        return {"CoreNetworkPolicy": self.raw["policy"]}

    def get_network_routes(self, **_):
        return {"NetworkRoutes": []}


@pytest.fixture
def env(monkeypatch):
    s3, table = FakeS3(), FakeTable()
    failing: set[str] = set()

    def client(service, region=None):
        if service == "s3":
            return s3
        if service == "ec2":
            return FakeEC2(region or "us-east-1", fail=region in failing)
        if service == "directconnect":
            return FakeDX(region or "us-east-1")
        if service == "networkmanager":
            assert region == "us-west-2"
            return FakeNM()
        raise AssertionError(service)

    monkeypatch.setattr(aws_clients, "client", client)
    monkeypatch.setattr(aws_clients, "table", lambda name: table)
    monkeypatch.setenv("BUCKET_NAME", BUCKET)
    monkeypatch.setenv("TABLE_NAME", TABLE)
    return s3, table, failing


def execute(started_at, failing_collect=(), inp=None):
    """Mimic the state machine: init, Map over Regions with Catch, then evaluate/diff/report."""
    init = init_run.handler({"execution_name": f"exec-{started_at}", "started_at": started_at, "input": inp or {}})
    base = {"run_id": init["run_id"]}
    cw = collect.cloudwan_handler(base) if init["collect_cloudwan"] else None
    results = []
    for region in init["regions"]:
        if region in failing_collect:
            results.append({"region": region, "status": "error", "reason": "States.TaskFailed: ThrottlingException"})
        else:
            results.append(collect.region_handler({**base, "region": region}))
    pipeline.evaluate_handler({**base, "cloudwan": cw, "regions": results})
    d = pipeline.diff_handler(base)
    rep = pipeline.report_handler(base)
    return init, d, rep


def test_full_pipeline_on_recording_new_then_known(env, capsys):
    s3, table, _ = env
    init, d1, rep1 = execute("2026-05-11T05:00:00Z")
    assert init["regions"] == ["eu-central-1", "eu-west-1", "us-east-1"]  # TGW Regions + Cloud WAN edge
    assert init["scope"] == "full" and init["collect_cloudwan"] is True
    manifest = s3.json(f"runs/{init['run_id']}/manifest.json")
    assert manifest["intent"]["status"] == "absent" and manifest["lookback_from"] == "2026-05-10T05:00:00Z"
    assert d1 == {"run_id": init["run_id"], "new_drift": 6, "known_drift": 0, "resolved_drift": 0}
    assert rep1["kind"] == "drift" and "6 new, 0 known, 0 resolved" in rep1["subject"]
    assert "No investigation was performed: DevOps Agent hand-off is not enabled." in rep1["body"]
    assert '"FindingsNew": 6' in capsys.readouterr().out

    assert rep1["complete"] is True and rep1["advance_marker"] is True

    init2, d2, rep2 = execute("2026-05-12T05:00:00Z")
    assert init2["run_id"] != init["run_id"]
    assert d2["new_drift"] == 0 and d2["known_drift"] == 6
    assert "(1 day)" in rep2["body"] and f"RUN#{init2['run_id']}" in table.items


@pytest.mark.parametrize("flag", ["true", "false"])
def test_init_returns_the_handoff_flag_for_the_state_machine_choice(env, monkeypatch, flag):
    monkeypatch.setenv("ENABLE_DEVOPS_AGENT_HANDOFF", flag)
    init = init_run.handler({"execution_name": "h", "started_at": "2026-05-12T05:00:00Z"})
    assert init["handoff_enabled"] is (flag == "true")


def test_report_treats_skipped_investigation_as_none(env):
    init, _, _ = execute("2026-05-11T05:00:00Z")
    rep = pipeline.report_handler({"run_id": init["run_id"], "investigation": {"status": "skipped"}})
    assert "No investigation was performed: DevOps Agent hand-off is not enabled." in rep["body"]


def test_report_renders_the_merged_investigation_from_s3(env):
    s3, _, _ = env
    init, _, _ = execute("2026-05-11T05:00:00Z")
    run_id = init["run_id"]
    merged = {"batches": [{"batch_n": 1, "status": "ok", "investigation_url": "https://x.example/inv/1"}],
              "incidents": [{"rank": 1, "title": "Orphaned static routes", "member_finding_ids": ["f-1"],
                             "root_cause_hypothesis": "h", "confidence": "high", "evidence": [],
                             "actor_identified": True, "stable_for": "P0D", "validation_commands": [],
                             "blast_radius": {"prefixes": 1, "attachments": 1, "domains": 1, "environment": "",
                                              "score": 111},
                             "investigation_url": "https://x.example/inv/1"}],
              "invariant": {"ok": True}}
    s3.put_object(Bucket=BUCKET, Key=f"runs/{run_id}/investigation.json", Body=json.dumps(merged).encode())
    rep = pipeline.report_handler({"run_id": run_id, "investigation": {"ok_batches": 1, "failed_batches": 0}})
    assert "1. Orphaned static routes" in rep["body"] and rep["subject"].endswith("(investigated)")


def test_report_still_publishes_when_the_investigation_result_is_unreadable(env):
    init, _, _ = execute("2026-05-11T05:00:00Z")
    rep = pipeline.report_handler({"run_id": init["run_id"],
                                   "investigation": {"batches": [{"batch_n": 1, "status": "ok"}]}})
    assert "Investigation failed: batch 1: result unreadable. Raw findings follow." in rep["body"]
    assert rep["subject"].endswith("(investigation failed)")


def test_region_not_evaluated_keeps_findings_known_and_reports_it(env):
    execute("2026-05-11T05:00:00Z")
    _, d, rep = execute("2026-05-12T05:00:00Z", failing_collect={"eu-central-1"})
    assert d["resolved_drift"] == 0 and d["known_drift"] == 6
    assert "Regions not evaluated: eu-central-1" in rep["body"]
    assert "not re-verified this run" in rep["body"]
    assert rep["scope"] == "full" and rep["complete"] is False and rep["advance_marker"] is False


def test_tgw_probe_failure_includes_region_fail_closed(env):
    _, _, failing = env
    failing.add("ap-south-1")
    init = init_run.handler({"execution_name": "e", "started_at": "2026-05-12T05:00:00Z"})
    assert "ap-south-1" in init["regions"]


def test_override_run_is_partial_and_uses_given_regions(env):
    init = init_run.handler({"execution_name": "e", "started_at": "2026-05-12T05:00:00Z",
                             "input": {"regions": ["us-east-1"], "lookback_from": "2026-05-01T00:00:00Z"}})
    assert init["scope"] == "partial" and init["regions"] == ["us-east-1"]
    base = {"run_id": init["run_id"]}
    cw = collect.cloudwan_handler(base)
    pipeline.evaluate_handler({**base, "cloudwan": cw,
                               "regions": [collect.region_handler({**base, "region": "us-east-1"})]})
    pipeline.diff_handler(base)
    rep = pipeline.report_handler(base)
    assert rep["complete"] is True and rep["advance_marker"] is False  # ad-hoc never moves the marker


def test_intent_file_present_and_rejected(env):
    s3, _, _ = env
    s3.put_object(BUCKET, "intent/routing-intent.yaml", b"version: 1\n")
    _, _, rep = execute("2026-05-11T05:00:00Z")
    assert "6 of 6 checks run" in rep["body"] and "checks skipped" not in rep["body"]
    s3.put_object(BUCKET, "intent/routing-intent.yaml", b"version: 1\n  bad: [\n")
    _, _, rep = execute("2026-05-12T05:00:00Z")
    assert "Intent file rejected: line" in rep["body"]


def test_intent_regions_replace_stack_lists_and_input_overrides_both(env, monkeypatch):
    """tasks.md 2.5: execution input > intent file > stack parameters > discovery."""
    s3 = env[0]
    monkeypatch.setenv("REGION_ALLOWLIST", "us-east-1")
    init = init_run.handler({"execution_name": "a", "started_at": "2026-05-12T05:00:00Z"})
    assert init["regions"] == ["us-east-1"]  # stack allowlist
    s3.put_object(BUCKET, "intent/routing-intent.yaml",
                  b"version: 1\nregions:\n  allow: [eu-central-1, eu-west-1]\n  exclude: [eu-west-1]\n")
    init = init_run.handler({"execution_name": "b", "started_at": "2026-05-12T05:00:00Z"})
    assert init["regions"] == ["eu-central-1"]  # intent allow replaces stack allowlist; intent exclude applied
    init = init_run.handler({"execution_name": "c", "started_at": "2026-05-12T05:00:00Z",
                             "input": {"regions": ["us-east-1"]}})
    assert init["regions"] == ["us-east-1"] and init["scope"] == "partial"  # execution input wins
    s3.put_object(BUCKET, "intent/routing-intent.yaml", b"version: 1\nregions:\n  allow: [nope]\n")
    init = init_run.handler({"execution_name": "d", "started_at": "2026-05-12T05:00:00Z"})
    assert init["regions"] == ["us-east-1"]  # rejected intent file: stack parameters still apply


def test_intent_vif_region_added_to_discovery_fail_closed(env, monkeypatch):
    """A VIF named in the intent file pulls its Region into scope even without a TGW there."""
    s3, _, _ = env
    original = aws_clients.client

    class VifDX(FakeDX):
        def describe_virtual_interfaces(self):
            if self.region == "ap-south-1":
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "DescribeVirtualInterfaces")
            owned = [{"virtualInterfaceId": "dxvif-0bbb"}] if self.region == "eu-west-1" else []
            return {"virtualInterfaces": owned}

    monkeypatch.setattr(aws_clients, "client",
                        lambda service, region=None: VifDX(region or "us-east-1") if service == "directconnect"
                        else original(service, region))
    s3.put_object(BUCKET, "intent/routing-intent.yaml",
                  b"version: 1\ndx_redundancy_pairs:\n  - name: p\n    members: [dxvif-0bbb, dxvif-0ccc]\n")
    init = init_run.handler({"execution_name": "v", "started_at": "2026-05-12T05:00:00Z"})
    # eu-west-1 has the VIF (and a TGW anyway); ap-south-1 could not be probed -> included, fail-closed
    assert "ap-south-1" in init["regions"] and "eu-west-1" in init["regions"]


def test_marker_used_as_lookback(env):
    _, table, _ = env
    table.items["META#marker"] = {"pk": "META#marker", "last_successful_full_run": "2026-05-09T05:00:00Z"}
    init = init_run.handler({"execution_name": "e", "started_at": "2026-05-12T05:00:00Z"})
    s3 = env[0]
    assert s3.json(f"runs/{init['run_id']}/manifest.json")["lookback_from"] == "2026-05-09T05:00:00Z"


def test_init_degrades_visibly_when_cloudwan_and_dx_discovery_fail(env, monkeypatch):
    original = aws_clients.client

    class Broken:
        def get_paginator(self, op):
            raise ClientError({"Error": {"Code": "AccessDeniedException"}}, op)

    def client(service, region=None):
        return Broken() if service in ("networkmanager", "directconnect") else original(service, region)

    monkeypatch.setattr(aws_clients, "client", client)
    init = init_run.handler({"execution_name": "e", "started_at": "2026-05-12T05:00:00Z"})
    manifest = env[0].json(f"runs/{init['run_id']}/manifest.json")
    assert manifest["cloudwan"]["status"] == "unknown" and manifest["dx_gateways"]["status"] == "error"
    assert init["collect_cloudwan"] is True  # unknown is collected (and fails visibly), never skipped


def test_unreadable_intent_is_reported(env, monkeypatch):
    s3 = env[0]
    real_get = s3.get_object

    def get(Bucket, Key):  # noqa: N803
        if Key.startswith("intent/"):
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
        return real_get(Bucket, Key)

    monkeypatch.setattr(s3, "get_object", get)
    _, _, rep = execute("2026-05-12T05:00:00Z")
    assert "Intent file unreadable: could not read the intent file (AccessDenied)" in rep["body"]


def test_cloudwan_collection_failure_reported(env):
    init = init_run.handler({"execution_name": "e", "started_at": "2026-05-12T05:00:00Z"})
    base = {"run_id": init["run_id"]}
    results = [collect.region_handler({**base, "region": r}) for r in init["regions"]]
    pipeline.evaluate_handler({**base, "cloudwan": {"status": "error", "reason": "States.Timeout"},
                               "regions": results[:-1]})
    pipeline.diff_handler(base)
    body = pipeline.report_handler(base)["body"]
    assert "Cloud WAN not evaluated: collection timed out (States.Timeout)" in body
    assert "Region us-east-1 not evaluated: no collection result" in body


def test_region_collect_raises_classified_error(env):
    """What the live fault injection showed: the error NAME reaching Step Functions must be specific."""
    from drift_core.collectors.errors import CollectionAccessDenied, CollectionThrottled

    _, _, failing = env
    init = init_run.handler({"execution_name": "e", "started_at": "2026-05-12T05:00:00Z"})
    failing.add("eu-central-1")  # FakeEC2 raises ThrottlingException
    with pytest.raises(CollectionThrottled):
        collect.region_handler({"run_id": init["run_id"], "region": "eu-central-1"})

    original = aws_clients.client

    class Denied(FakeEC2):
        def get_paginator(self, op):
            raise ClientError({"Error": {"Code": "UnauthorizedOperation"}}, op)

    def client(service, region=None):
        return Denied(region) if service == "ec2" else original(service, region)

    import handlers.collect as hc
    hc.aws_clients.client = client
    try:
        with pytest.raises(CollectionAccessDenied):
            collect.region_handler({"run_id": init["run_id"], "region": "us-east-1"})
    finally:
        hc.aws_clients.client = original


def test_handlers_reject_missing_run_id(env):
    from drift_core.run_info import InputError

    for fn in (collect.cloudwan_handler, pipeline.evaluate_handler, pipeline.diff_handler, pipeline.report_handler):
        with pytest.raises(InputError):
            fn({})
    with pytest.raises(InputError):
        collect.region_handler({"run_id": "r", "region": "not a region"})
