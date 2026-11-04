# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tools against fake AWS clients, plus table schemes, S3 layout and configuration."""

import gzip
import io
import json
from datetime import UTC, date, datetime

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from network_flow_insight import aws_backend
from network_flow_insight.config import Settings, load_settings
from network_flow_insight.core import s3layout
from network_flow_insight.core.athena import AthenaEngine, CostGauge, GaugedEngine
from network_flow_insight.core.inventory import (
    Inventory,
    InventoryError,
    config_agg,
    load_file,
    load_provider,
)
from network_flow_insight.core.tablescheme import (
    DEFAULT_FIELDS,
    TableScheme,
    detect_scheme,
    projection_ddl,
    refine_day_kind,
    window_days,
)
from network_flow_insight.demo import estate as E
from network_flow_insight.demo.localfs import LocalS3
from network_flow_insight.tools import (
    create_table,
    get_gateway_metrics,
    get_inventory,
    get_ip_ranges,
    get_prices,
    list_log_prefixes,
    probe_table,
    query_cur,
    query_resolver_logs,
    to_units,
    write_report,
)
from tests.unit.test_e8_e10_gauge_intent_chat import FakeAthena

# ------------------------------------------------------------------------------ table schemes


def test_window_predicates_for_each_partition_layout():
    slash = TableScheme("db", "t", day_kind="slash")
    assert slash.window_predicate("2026-03-02", "2026-03-08") == "day BETWEEN '2026/03/02' AND '2026/03/08'"
    assert (
        TableScheme("db", "t", day_kind="dash").window_predicate("2026-03-02", "2026-03-02")
        == "day BETWEEN '2026-03-02' AND '2026-03-02'"
    )
    assert "DATE '2026-03-02'" in TableScheme("db", "t", day_kind="date").window_predicate(
        "2026-03-02", "2026-03-08"
    )
    ymd = TableScheme("db", "t", day_kind="ymd", day_col="day", year_col="year", month_col="month")
    assert "BETWEEN 20260302 AND 20260308" in ymd.window_predicate("2026-03-02", "2026-03-08")
    assert "lpad" in ymd.day_expr()
    with pytest.raises(ValueError):
        slash.window_predicate("2026-03-08", "2026-03-02")
    assert window_days("2026-02-27", "2026-03-02") == ["2026-02-27", "2026-02-28", "2026-03-01", "2026-03-02"]


def test_unsafe_identifiers_are_refused():
    with pytest.raises(ValueError):
        TableScheme("db; drop", "t")
    with pytest.raises(ValueError):
        projection_ddl(
            database="db",
            table="t",
            bucket="Bad_Bucket",
            fields=DEFAULT_FIELDS,
            accounts=["123456789012"],
            regions=["eu-west-2"],
            first_day="2026-03-01",
        )
    with pytest.raises(ValueError):
        projection_ddl(
            database="db",
            table="t",
            bucket="ok-bucket",
            fields=DEFAULT_FIELDS,
            accounts=["1'2"],
            regions=["eu-west-2"],
            first_day="2026-03-01",
        )


def test_detect_scheme_from_glue_schema():
    cols = [c.replace("_", "-") for c in DEFAULT_FIELDS]
    s = detect_scheme("db", "t", cols, ["aws-account-id", "aws-region", "year", "month", "day"], "parquet")
    assert s.day_kind == "ymd" and s.account_col == "aws_account_id" and s.region_col == "aws_region"
    s2 = detect_scheme("db", "t", cols, ["date"])
    assert s2.day_col == "date" and s2.day_kind == "date"
    assert refine_day_kind(detect_scheme("db", "t", cols, ["day"]), "2026-03-02").day_kind == "dash"
    with pytest.raises(ValueError):
        detect_scheme("db", "t", cols, ["unrelated"])


@pytest.mark.parametrize("layout, file_format", [("standard", "text"), ("hive", "parquet")])
def test_projection_ddl(layout, file_format):
    ddl = projection_ddl(
        database="nfi_agent",
        table="flow",
        bucket="example-flow-logs",
        fields=DEFAULT_FIELDS,
        accounts=["123456789012", "123456789013"],
        regions=["eu-west-2"],
        first_day="2026-03-01",
        layout=layout,
        file_format=file_format,
        org_id="o-abc123",
    )
    assert "'projection.enabled'='true'" in ddl and "'agent-managed'='true'" in ddl
    assert "`part_account`" in ddl and "123456789012,123456789013" in ddl
    assert "/o-abc123/" in ddl
    if layout == "standard":
        assert "skip.header.line.count" in ddl and "${part_account}/vpcflowlogs/${part_region}/${day}" in ddl
    else:
        assert "STORED AS PARQUET" in ddl and "year=${p_year}/month=${p_month}/day=${p_day}" in ddl


# ------------------------------------------------------------------------------ S3 layout


def test_parse_key_variants():
    std = "AWSLogs/123456789012/vpcflowlogs/eu-west-2/2026/03/02/x.log.gz"
    hive = "AWSLogs/aws-account-id=123456789012/aws-service=vpcflowlogs/aws-region=eu-west-2/year=2026/month=03/day=02/hour=05/x.parquet"
    org = "pre/AWSLogs/o-abc123/123456789012/vpcflowlogs/eu-west-2/2026/03/02/x.log.gz"
    assert s3layout.parse_key(std).day == "2026-03-02"
    assert s3layout.parse_key(hive).layout == "hive"
    assert s3layout.parse_key(org).account_id == "123456789012"
    assert s3layout.parse_key("AWSLogs/other/thing") is None


def test_walk_lists_only_the_window_and_sums_bytes(estates):
    est = estates["full"]
    inv = list_log_prefixes.list_log_prefixes(LocalS3(est.s3_root), "b", "2026-03-02", "2026-03-04")
    assert inv.accounts == {E.ACCT_A, E.ACCT_B}
    assert inv.days == ["2026-03-02", "2026-03-03", "2026-03-04"]
    assert inv.file_format == "text" and inv.layout == "standard" and not inv.hourly
    assert inv.bytes_for(accounts={E.ACCT_B}) < inv.bytes_for()
    est_bytes = s3layout.estimate_bytes(inv, "2026-03-02", "2026-03-02")
    assert 0 < est_bytes < inv.bytes_for()
    assert len(inv.summary()["partitions"]) == 6
    first, last = s3layout.previous_complete_days(date(2026, 3, 9), 7)
    assert (first, last) == ("2026-03-02", "2026-03-08")


def test_detect_fields_from_first_object(estates):
    inv = s3layout.walk(LocalS3(estates["enhanced"].s3_root), "b", "2026-03-02", "2026-03-02")
    fields = s3layout.detect_fields(LocalS3(estates["enhanced"].s3_root), inv)
    assert "pkt_srcaddr" in fields and "log_status" in fields and "traffic_path" not in fields


def test_detect_fields_parquet_and_empty(tmp_path):
    t = pa.table({"account-id": ["1"], "interface-id": ["e"], "bytes": [1]})
    p = (
        tmp_path
        / "AWSLogs"
        / "123456789012"
        / "vpcflowlogs"
        / "eu-west-2"
        / "2026"
        / "03"
        / "02"
        / "a.parquet"
    )
    p.parent.mkdir(parents=True)
    pq.write_table(t, p)
    s3 = LocalS3(tmp_path)
    inv = s3layout.walk(s3, "b", "2026-03-02", "2026-03-02")
    assert inv.file_format == "parquet"
    assert s3layout.detect_fields(s3, inv) == ("account_id", "interface_id", "bytes")
    with pytest.raises(ValueError):
        s3layout.detect_fields(s3, s3layout.LogInventory("b"))


# ------------------------------------------------------------------------------ Glue probe


class FakeGlue:
    def __init__(self, table, partitions=None, databases=("db",)):
        self.table, self.parts, self.dbs = table, partitions or [], databases
        self.created = []

    def get_table(self, DatabaseName, Name):  # noqa: N803
        if Name == "missing":
            raise _ClientError("EntityNotFoundException")
        return {"Table": self.table}

    def get_paginator(self, op):
        outer = self

        class P:
            def paginate(self, **kw):
                if op == "get_partitions":
                    yield {"Partitions": [{"Values": v} for v in outer.parts]}
                elif op == "get_databases":
                    yield {"DatabaseList": [{"Name": d} for d in outer.dbs]}
                elif op == "get_tables":
                    yield {"TableList": [outer.table]}

        return P()

    def get_database(self, Name):  # noqa: N803
        if Name != "exists":
            raise _ClientError("EntityNotFoundException")
        return {}

    def create_database(self, DatabaseInput):  # noqa: N803
        self.created.append(DatabaseInput["Name"])


class _ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def _glue_table(partition_keys, params=None, parquet=False):
    cols = [{"Name": c.replace("_", "-")} for c in DEFAULT_FIELDS]
    return {
        "Name": "flow",
        "StorageDescriptor": {
            "Columns": cols,
            "Location": "s3://example-flow-logs/AWSLogs/",
            "SerdeInfo": {"SerializationLibrary": "parquet.ParquetHiveSerDe" if parquet else "lazy"},
        },
        "PartitionKeys": [{"Name": k} for k in partition_keys],
        "Parameters": params or {},
    }


def test_probe_projection_table():
    params = {
        "projection.enabled": "true",
        "projection.part_account.type": "enum",
        "projection.part_account.values": "123456789012,123456789013",
        "projection.part_region.type": "enum",
        "projection.part_region.values": "eu-west-2",
        "projection.day.type": "date",
        "projection.day.format": "yyyy/MM/dd",
        "projection.day.range": "2026/02/01,NOW",
    }
    out = probe_table.probe_table(
        FakeGlue(_glue_table(["part_account", "part_region", "day"], params)),
        "db",
        "flow",
        "2026-03-02",
        "2026-03-08",
    )
    v = out["visibility_full"]
    assert (
        out["projection"] and v["mode"] == "projection" and v["accounts"] == ["123456789012", "123456789013"]
    )
    assert v["first_day"] == "2026-02-01" and out["scheme"]["day_kind"] == "slash"
    assert probe_table.scheme_from_dict(out["scheme"]).day_col == "day"
    assert not out["recommendations"]


def test_probe_enumerated_table_and_recommendation():
    parts = [["123456789012", "eu-west-2", "2026/03/02"], ["123456789012", "eu-west-2", "2026/03/03"]]
    out = probe_table.probe_table(
        FakeGlue(_glue_table(["account", "region", "day"]), parts), "db", "flow", "2026-03-02", "2026-03-08"
    )
    assert out["visibility_full"]["mode"] == "enumerated"
    assert out["visibility_full"]["partitions"][0] == ["123456789012", "eu-west-2", "2026-03-02"]
    assert out["days_with_partitions"] == ["2026-03-02", "2026-03-03"]
    assert "Partition projection" in out["recommendations"][0]


def test_probe_with_skipdata_sample(estates):
    from network_flow_insight.demo.duck import DuckDBEngine

    duck = DuckDBEngine(estates["full"].s3_root, "nfi", "flow_logs")
    eng = GaugedEngine(duck, CostGauge(5.0, 5.0, 50.0))
    inv = s3layout.walk(LocalS3(estates["full"].s3_root), "b", "2026-03-04", "2026-03-04")
    sample = probe_table._skipdata_sample(eng, duck.scheme, inv, "2026-03-04")
    assert sample["skipdata_records"] == 20 and sample["execution_id"].startswith("duckdb-")


def test_find_flow_log_tables():
    found = probe_table.find_flow_log_tables(FakeGlue(_glue_table(["day"])))
    assert found == [{"database": "db", "table": "flow", "location": "s3://example-flow-logs/AWSLogs/"}]


def test_ensure_agent_database_requires_confirmation():
    g = FakeGlue(_glue_table(["day"]))
    with pytest.raises(aws_backend.SetupNeeded):
        aws_backend._ensure_agent_database(g, "nfi_agent", False)
    aws_backend._ensure_agent_database(g, "nfi_agent", True)
    assert g.created == ["nfi_agent"]
    aws_backend._ensure_agent_database(g, "exists", False)


# ------------------------------------------------------------------------------ create path


class FakeAthenaAdmin(FakeAthena):
    def __init__(self):
        super().__init__()
        self.workgroups = []

    def create_work_group(self, **kw):
        self.workgroups.append(kw)

    def get_work_group(self, WorkGroup):  # noqa: N803
        return {
            "WorkGroup": {
                "Configuration": {
                    "EnforceWorkGroupConfiguration": True,
                    "ResultConfiguration": {"OutputLocation": "s3://r/"},
                }
            }
        }


def test_create_table_shows_plan_then_creates_only_when_confirmed(estates):
    est = estates["enhanced"]
    s3 = LocalS3(est.s3_root)
    inv = s3layout.walk(s3, "example-flow-logs", "2026-03-02", "2026-03-03")
    glue, athena = FakeGlue(_glue_table(["day"])), FakeAthenaAdmin()
    kw = dict(
        glue=glue,
        athena=athena,
        s3=s3,
        log_inventory=inv,
        first_day="2026-03-01",
        agent_database="nfi_agent",
        table="nfi_flow_logs",
        workgroup="nfi-agent",
        results_location="s3://r/",
    )
    plan = create_table.create_table(**kw, confirmed=False)
    assert (
        plan["status"] == "needs-confirmation"
        and not glue.created
        and not athena.workgroups
        and athena.n == 0
    )
    assert "pkt_srcaddr" in plan["plan"]["fields"] and plan["plan"]["tags"]["agent-managed"] == "true"
    done = create_table.create_table(**kw, confirmed=True)
    assert (
        done["status"] == "created"
        and glue.created == ["nfi_agent"]
        and athena.workgroups[0]["Name"] == "nfi-agent"
    )
    assert athena.workgroups[0]["Configuration"]["EnforceWorkGroupConfiguration"] is True
    assert any(sql.startswith("CREATE EXTERNAL TABLE") for sql in athena.sql.values())


def test_ctas_omits_external_location_when_workgroup_enforces_output():
    fake = FakeAthena()
    AthenaEngine(fake, "wg", "s3://r/", "db", enforce_output=True).ctas("db.t", "SELECT 1", "s3://r/x/")
    assert "external_location" not in next(iter(fake.sql.values()))
    fake2 = FakeAthena()
    AthenaEngine(fake2, "wg", "s3://r/", "db").ctas("db.t", "SELECT 1", "s3://r/x")
    assert "external_location='s3://r/x/'" in next(iter(fake2.sql.values()))
    with pytest.raises(ValueError):
        AthenaEngine(fake, "wg").ctas("db.t", "SELECT 1", "file:///etc")


# ------------------------------------------------------------------------------ prices, metrics, CUR, Resolver


class FakePricing:
    def __init__(self):
        def item(usagetype, usd, unit="GB", extra=None, tiers=None):
            dims = {
                f"d{i}": {"beginRange": str(b), "unit": unit, "pricePerUnit": {"USD": str(p)}}
                for i, (b, p) in enumerate(tiers or [(0, usd)])
            }
            return json.dumps(
                {
                    "product": {"attributes": {"usagetype": usagetype, **(extra or {})}},
                    "terms": {"OnDemand": {"t": {"priceDimensions": dims}}},
                }
            )

        self.items = {
            ("AmazonEC2", "NAT Gateway"): [
                item("EUW2-NatGateway-Bytes", 0.05),
                item("EUW2-NatGateway-Hours", 0.045, "Hrs"),
            ],
            ("AmazonVPC", None): [
                item("EUW2-VpcEndpoint-Bytes", 0.01),
                item("EUW2-TransitGateway-Bytes", 0.02),
            ],
            ("AWSDataTransfer", None): [
                item("EUW2-DataTransfer-Regional-Bytes", 0.01, extra={"transferType": "IntraRegion"}),
                item(
                    "EUW2-AWS-Out-Bytes",
                    0.09,
                    extra={"transferType": "AWS Outbound"},
                    tiers=[(0, 0.0), (100, 0.09)],
                ),
                item("EUW2-USE1-AWS-Out-Bytes", 0.02, extra={"transferType": "InterRegion Outbound"}),
                item("EUW2-APS1-AWS-Out-Bytes", 0.08, extra={"transferType": "InterRegion Outbound"}),
                item("EUW2-EUC1-AWS-Out-Bytes", 0.0, extra={"transferType": "InterRegion Outbound"}),
            ],
            ("AmazonAthena", None): [item("EUW2-DataScannedInTB", 5.0, "Terabytes")],
        }

    def get_products(self, ServiceCode, Filters, **_):  # noqa: N803
        fam = next((f["Value"] for f in Filters if f["Field"] == "productFamily"), None)
        return {"PriceList": self.items.get((ServiceCode, fam), self.items.get((ServiceCode, None), []))}


def test_get_prices_parses_price_list_items():
    r = get_prices.get_prices(FakePricing(), "eu-west-2")
    assert r["nat_processing_per_gb"] == 0.05 and r["interface_endpoint_per_gb"] == 0.01
    assert (
        r["inter_az_per_gb"] == 0.01 and r["internet_out_per_gb"] == 0.09
    )  # first paid tier, not the free one
    assert r["inter_region_per_gb"] == 0.02 and r["inter_region_range"] == [0.02, 0.08]
    assert r["athena_per_tb"] == 5.0 and r["gateway_endpoint_per_gb"] == 0.0
    with pytest.raises(ValueError):
        get_prices.get_prices(FakePricing(), "xx-nowhere-1")


class FakeCloudWatch:
    def __init__(self, values):
        self.values = values

    def get_metric_data(self, MetricDataQueries, **_):  # noqa: N803
        return {
            "MetricDataResults": [
                {"Id": q["Id"], "Values": self.values.get(q["MetricStat"]["Metric"]["MetricName"], [])}
                for q in MetricDataQueries
            ]
        }

    def list_metrics(self, **_):
        return {"Metrics": [{"Dimensions": [{"Name": "VPC Endpoint Id", "Value": "vpce-1"}]}]}


def test_gateway_metrics_sum_windows_and_report_unavailable():
    cw = FakeCloudWatch(
        {
            "BytesOutToDestination": [10, 20],
            "BytesInFromDestination": [100],
            "BytesInFromSource": [30],
            "BytesOutToSource": [100],
            "BytesProcessed": [7],
            "BytesIn": [1],
            "BytesOut": [2],
        }
    )
    out = get_gateway_metrics.get_gateway_metrics(
        cw,
        [
            {"kind": "nat", "id": "nat-1"},
            {"kind": "endpoint", "id": "vpce-1"},
            {"kind": "tgw", "id": "tgw-a"},
        ],
        "2026-03-02",
        "2026-03-08",
    )
    assert (
        out["nat-1"]["comparable_bytes"] == 130
        and out["vpce-1"]["comparable_bytes"] == 7
        and out["tgw-a"]["comparable_bytes"] == 3
    )
    assert isinstance(
        get_gateway_metrics.get_gateway_metrics(
            FakeCloudWatch({}), [{"kind": "nat", "id": "nat-1"}], "2026-03-02", "2026-03-08"
        ),
        str,
    )
    assert isinstance(get_gateway_metrics.get_gateway_metrics(cw, [], "2026-03-02", "2026-03-08"), str)

    class Boom:
        def get_metric_data(self, **_):
            raise RuntimeError("AccessDenied")

    assert "failed" in get_gateway_metrics.get_gateway_metrics(
        Boom(), [{"kind": "nat", "id": "n"}], "2026-03-02", "2026-03-08"
    )


class StubEngine:
    def __init__(self, rows=None, raises=None):
        self.rows, self.raises, self.sql = rows or [], raises, []

    def run(self, sql, *, estimated_bytes, label="", max_rows=None):
        if self.raises:
            raise self.raises
        self.sql.append(sql)
        from network_flow_insight.core.athena import QueryResult

        return QueryResult(self.rows, [], "q-1", 1, sql)


def test_cur_and_resolver_queries_are_validated_and_degrade_gracefully():
    eng = StubEngine([{"account_id": 123456789012, "usage_type": "EUW2-NatGateway-Bytes", "usage_gb": 1.5}])
    rows = query_cur.query_cur(eng, "cur_db", "cur", "2026-03-02", "2026-03-08", ["123456789012"])
    assert rows == [{"account_id": "123456789012", "usage_type": "EUW2-NatGateway-Bytes", "usage_gb": 1.5}]
    assert "line_item_usage_account_id IN ('123456789012')" in eng.sql[0]
    assert isinstance(
        query_cur.query_cur(
            StubEngine(raises=RuntimeError("denied")), "d", "t", "2026-03-02", "2026-03-08", ["1"]
        ),
        str,
    )
    with pytest.raises(ValueError):
        query_cur.query_cur(eng, "d; drop", "t", "2026-03-02", "2026-03-08", ["1"])

    res = StubEngine(
        [
            {"ip": "198.18.32.5", "query_name": "a.example.", "last_seen": "x"},
            {"ip": "198.18.32.5", "query_name": "b.example.", "last_seen": "y"},
        ]
    )
    names = query_resolver_logs.query_resolver_logs(
        res, "d", "resolver", ["198.18.32.5"], "2026-03-02", "2026-03-08"
    )
    assert names == {"198.18.32.5": ["a.example", "b.example"]}
    assert query_resolver_logs.query_resolver_logs(res, "d", "resolver", [], "2026-03-02", "2026-03-08") == {}
    assert isinstance(
        query_resolver_logs.query_resolver_logs(
            StubEngine(raises=RuntimeError("x")), "d", "r", ["1.2.3.4"], "2026-03-02", "2026-03-08"
        ),
        str,
    )


# ------------------------------------------------------------------------------ inventory providers


class FakeConfig:
    def __init__(self, pages):
        self.pages = pages

    def select_aggregate_resource_config(self, **kw):
        return self.pages.pop(0)


def _cfg_row(rtype, rid, conf, acct="123456789012", region="eu-west-2"):
    return json.dumps(
        {
            "resourceType": rtype,
            "resourceId": rid,
            "accountId": acct,
            "awsRegion": region,
            "configuration": conf,
        }
    )


def test_config_aggregator_provider_maps_resources():
    pages = [
        {
            "Results": [
                _cfg_row(
                    "AWS::EC2::VPC",
                    "vpc-1",
                    {"cidrBlock": "10.0.0.0/16", "cidrBlockAssociationSet": [{"cidrBlock": "10.0.0.0/16"}]},
                ),
                _cfg_row(
                    "AWS::EC2::Subnet",
                    "subnet-1",
                    {"vpcId": "vpc-1", "cidrBlock": "10.0.1.0/24", "availabilityZoneId": "euw2-az1"},
                ),
                _cfg_row(
                    "AWS::EC2::RouteTable",
                    "rt-1",
                    {
                        "vpcId": "vpc-1",
                        "associations": [{"subnetId": "subnet-1"}],
                        "routes": [
                            {"destinationCidrBlock": "0.0.0.0/0", "natGatewayId": "nat-1", "state": "active"},
                            {"destinationPrefixListId": "pl-1", "gatewayId": "vpce-1"},
                        ],
                    },
                ),
                _cfg_row(
                    "AWS::EC2::NetworkInterface",
                    "eni-n",
                    {
                        "interfaceType": "nat_gateway",
                        "vpcId": "vpc-1",
                        "subnetId": "subnet-1",
                        "privateIpAddresses": [
                            {"privateIpAddress": "10.0.1.9"},
                            {"privateIpAddress": "10.0.1.10"},
                        ],
                    },
                ),
                _cfg_row(
                    "AWS::EC2::NetworkInterface",
                    "eni-w",
                    {
                        "interfaceType": "interface",
                        "vpcId": "vpc-1",
                        "subnetId": "subnet-1",
                        "privateIpAddresses": [{"privateIpAddress": "10.0.1.50"}],
                    },
                ),
            ],
            "NextToken": "n",
        },
        {
            "Results": [
                _cfg_row(
                    "AWS::EC2::NatGateway",
                    "nat-1",
                    {
                        "vpcId": "vpc-1",
                        "subnetId": "subnet-1",
                        "state": "available",
                        "natGatewayAddresses": [
                            {"networkInterfaceId": "eni-n", "privateIp": "10.0.1.9", "publicIp": "192.0.2.1"}
                        ],
                    },
                ),
                _cfg_row(
                    "AWS::EC2::VPCEndpoint",
                    "vpce-1",
                    {
                        "vpcId": "vpc-1",
                        "vpcEndpointType": "Gateway",
                        "serviceName": "com.amazonaws.eu-west-2.s3",
                    },
                ),
                _cfg_row(
                    "AWS::EC2::TransitGatewayAttachment",
                    "tgw-a",
                    {"transitGatewayId": "tgw-1", "resourceType": "vpc", "resourceId": "vpc-1"},
                ),
            ]
        },
    ]
    doc = config_agg.collect(FakeConfig(pages), "agg")
    inv = Inventory(doc)
    assert inv.nat_addresses() == {"10.0.1.9", "10.0.1.10"}
    assert inv.route_for("subnet-1", "8.8.8.8")["target_type"] == "nat-gateway"
    assert inv.subnets["subnet-1"]["route_table_id"] == "rt-1"
    assert inv.route_for("subnet-1", "10.9.9.9")["target_type"] == "nat-gateway"
    assert doc["endpoints"][0]["type"] == "Gateway" and doc["tgw_attachments"][0]["vpc_id"] == "vpc-1"


def test_inventory_file_provider_and_selection(estates, tmp_path):
    inv = load_file(estates["full"].inventory_path)
    assert inv.nat_interface_ids() == ["eni-0nat1"]
    letter, loaded, note = load_provider("file", inventory_file=str(estates["full"].inventory_path))
    assert letter == "C" and loaded and "file" in note
    letter, loaded, note = load_provider("auto")
    assert letter == "D" and loaded is None
    with pytest.raises(InventoryError):
        load_provider("bogus")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": 2}))
    with pytest.raises(InventoryError):
        load_file(bad)
    with pytest.raises(InventoryError):
        load_file(tmp_path / "nope.json")
    _, inv2, summary = get_inventory.get_inventory("none")
    assert inv2 is None and "D" in summary["options"]


def test_inventory_validation_rejects_unknown_roles(estates):
    doc = json.loads(estates["full"].inventory_path.read_text())
    doc["interfaces"][0]["role"] = "toaster"
    with pytest.raises(InventoryError):
        Inventory(doc)


def test_auto_provider_falls_through_with_notes():
    class Sess:
        def client(self, name, region_name=None):
            raise RuntimeError("no credentials")

    letter, inv, note = load_provider("auto", session=Sess(), region="eu-west-2", aggregator="agg")
    assert letter == "D" and inv is None and "unavailable" in note
    with pytest.raises(RuntimeError):
        load_provider("ec2", session=Sess(), region="eu-west-2")


# ------------------------------------------------------------------------------ ip ranges, reports, units, config


def test_ip_ranges_https_only_and_local_file(estates, tmp_path):
    with pytest.raises(ValueError):
        get_ip_ranges.get_ip_ranges("http://ip-ranges.amazonaws.com/ip-ranges.json")
    r = get_ip_ranges.get_ip_ranges("https://unused", local_file=str(estates["full"].ip_ranges_path))
    assert r.lookup(E.S3_LOCAL[0]).specific_services == ("S3",)
    from network_flow_insight.core import ipranges

    cache = tmp_path / "ip-ranges.json"
    cache.write_text(json.dumps(E.ip_ranges_document()))
    assert ipranges.fetch_document("https://never-fetched.example", tmp_path)["syncToken"] == "1772000000"
    assert (
        ipranges.is_private("10.1.2.3")
        and not ipranges.is_private("203.0.113.5")
        and not ipranges.is_private("nope")
    )


def test_write_report_local_and_s3(tmp_path):
    class S3Put:
        def __init__(self):
            self.puts = []

        def put_object(self, **kw):
            self.puts.append(kw)

    r = write_report.write_report({"a/b.md": "x", "c.csv": b"1"}, local_dir=str(tmp_path))
    assert (tmp_path / "a" / "b.md").read_text() == "x" and r["count"] == 2
    s3 = S3Put()
    r2 = write_report.write_report({"report.md": "x"}, s3=s3, bucket="rb", prefix="reports/describe/")
    assert r2["written"] == ["s3://rb/reports/describe/report.md"]
    # No per-object encryption header: the report bucket's default (customer-managed KMS key) applies.
    assert "ServerSideEncryption" not in s3.puts[0] and s3.puts[0]["ContentType"] == "text/markdown"


def test_units_and_config(tmp_path, monkeypatch):
    assert to_units.to_units(1_500_000_000)["text"] == "1.5 GB"
    assert to_units.to_units(999)["text"] == "999 B" and to_units.to_units(None)["text"] == "n/a"
    toml = tmp_path / "nfi.toml"
    toml.write_text('flow_log_bucket = "from-file"\nscan_ceiling_usd = 7.5\nunknown = 1\n')
    s = load_settings(
        env={"NFI_FLOW_LOG_TABLE": "t", "BEDROCK_REGION": "eu-west-1", "NFI_ALLOW_NO_GUARDRAIL": "true"},
        toml_path=toml,
    )
    assert (
        s.flow_log_bucket,
        s.scan_ceiling_usd,
        s.flow_log_table,
        s.bedrock_region,
        s.allow_no_guardrail,
    ) == ("from-file", 7.5, "t", "eu-west-1", True)
    assert s.bedrock_model_id == "eu.anthropic.claude-sonnet-5"
    assert load_settings(env={"NFI_FLOW_LOG_BUCKET": "env"}, toml_path=toml).flow_log_bucket == "env"
    assert Settings().with_overrides(flow_log_bucket="x", nonsense=1).flow_log_bucket == "x"


def test_read_parquet_location_reads_every_data_file():
    table = pa.table({"day": ["2026-03-02"], "bytes": [5]})
    buf = io.BytesIO()
    pq.write_table(table, buf)

    class S3:
        def list_objects_v2(self, **kw):
            return {
                "Contents": [
                    {"Key": "p/_SUCCESS", "Size": 0},
                    {"Key": "p/20260309_1", "Size": 9},
                    {"Key": "p/20260309_2", "Size": 9},
                ],
                "IsTruncated": False,
            }

        def get_object(self, Bucket, Key):  # noqa: N803
            return {"Body": io.BytesIO(buf.getvalue())}

    rows = aws_backend.read_parquet_location(S3(), "s3://b/p")
    assert rows == [{"day": "2026-03-02", "bytes": 5}] * 2


def test_gzip_text_header_reader():
    body = gzip.compress(
        b"version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status\n1 2 3\n"
    )

    class S3:
        def get_object(self, **kw):
            return {"Body": io.BytesIO(body)}

    assert s3layout.read_text_header(S3(), "b", "k")[:3] == ["version", "account_id", "interface_id"]
    assert datetime(2026, 3, 2, tzinfo=UTC).date().isoformat() == "2026-03-02"


# ------------------------------------------------------------------------------ aggregate registration


def test_find_and_build_aggregate_on_athena(estates):
    from network_flow_insight.core.aggregate import aggregate_table_name, source_tag
    from network_flow_insight.tools import build_aggregate

    name = aggregate_table_name("2026-03-02", "2026-03-08", "db.flow")

    class G(FakeGlue):
        def get_table(self, DatabaseName, Name):  # noqa: N803
            if Name == name:
                return {"Table": {"StorageDescriptor": {"Location": "s3://r/nfi/aggregate/window=x/"}}}
            raise _ClientError("EntityNotFoundException")

    g = G(_glue_table(["day"]))
    assert build_aggregate.find_aggregate(g, "nfi_agent", "2026-03-02", "2026-03-08", source="db.flow")["reused"] is True
    assert build_aggregate.find_aggregate(g, "nfi_agent", "2026-03-09", "2026-03-15", source="db.flow") is None
    assert build_aggregate.find_aggregate(g, "nfi_agent", "2026-03-02", "2026-03-08", source="db.other") is None

    fake = FakeAthena()
    eng = GaugedEngine(
        AthenaEngine(fake, "wg", "s3://r/", "nfi_agent", enforce_output=False), CostGauge(5.0, 5.0, 50.0)
    )
    inv = s3layout.walk(LocalS3(estates["full"].s3_root), "b", "2026-03-02", "2026-03-08")
    scheme = TableScheme("db", "flow", tuple(DEFAULT_FIELDS))
    out = build_aggregate.build_aggregate(
        scheme, "2026-03-02", "2026-03-08", eng, inv, agg_database="nfi_agent", results_prefix="s3://r/"
    )
    sql = next(iter(fake.sql.values()))
    assert out["aggregate_table"] == name and out["estimated_bytes"] == inv.bytes_for()
    assert sql.startswith(f"CREATE TABLE nfi_agent.{name} WITH (format='PARQUET'")
    assert "day BETWEEN '2026/03/02' AND '2026/03/08'" in sql and "GROUP BY" in sql
    assert out["location"] == f"s3://r/nfi/aggregate/source={source_tag('db.flow')}/window=2026-03-02_2026-03-08/"


def test_discover_finds_accounts_regions_days_without_a_window(estates):
    inv = s3layout.discover(LocalS3(estates["full"].s3_root), "b")
    assert inv.accounts == {E.ACCT_A, E.ACCT_B} and inv.regions == {E.REGION}
    assert inv.days[0] == "2026-02-23" and inv.days[-1] == "2026-03-08" and len(inv.days) == 14
    assert inv.sample_key.endswith(".log.gz")


def test_log_inventory_merge_extends_the_estimate_to_another_window(estates):
    s3 = LocalS3(estates["full"].s3_root)
    inv = s3layout.walk(s3, "b", "2026-03-02", "2026-03-08")
    assert s3layout.estimate_bytes(inv, "2026-02-23", "2026-03-01") == 0  # the gauge would see a free scan
    inv.merge(s3layout.walk(s3, "b", "2026-02-23", "2026-03-01"))
    assert s3layout.estimate_bytes(inv, "2026-02-23", "2026-03-01") > 0
    assert len(inv.days) == 14


# ------------------------------------------------------------------------------ S3 config files, model config, tool output


class S3Files:
    def __init__(self, files):
        self.files = files

    def get_object(self, Bucket, Key):  # noqa: N803
        return {"Body": io.BytesIO(self.files[f"{Bucket}/{Key}"].encode())}


def test_config_files_can_live_in_s3(estates):
    from network_flow_insight.core.fileio import read_text
    from network_flow_insight.core.intent_schema import load_intent

    inv_doc = estates["full"].inventory_path.read_text()
    s3 = S3Files(
        {
            "cfg/inv.json": inv_doc,
            "cfg/intent.yaml": estates["full"].intent_path.read_text(),
            "cfg/r.json": '{"prefixes": []}',
        }
    )
    assert load_file("s3://cfg/inv.json", s3).nat_interface_ids() == ["eni-0nat1"]
    assert load_intent("s3://cfg/intent.yaml", s3).networks[0].name == "on-prem-dc1"
    assert (
        get_ip_ranges.get_ip_ranges("https://unused", local_file="s3://cfg/r.json", s3=s3).lookup("1.2.3.4")
        is None
    )
    with pytest.raises(ValueError):
        read_text("s3://bucket-only", s3)


def test_model_temperature_is_only_sent_when_configured(monkeypatch):
    from network_flow_insight import agent as agent_mod

    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr("strands.models.bedrock.BedrockModel", Fake)
    agent_mod.build_model(Settings(allow_no_guardrail=True))
    assert (
        "temperature" not in seen and "guardrail_id" not in seen
    )  # some models, for example Claude Sonnet 5, reject temperature
    agent_mod.build_model(Settings(guardrail_id="gr-1", guardrail_version="2", bedrock_temperature=0.0))
    assert seen["temperature"] == 0.0 and seen["guardrail_id"] == "gr-1" and seen["guardrail_version"] == "2"


def test_tool_output_carries_labelled_unit_text_next_to_bytes():
    from network_flow_insight.toolset import cap

    out = cap(
        {"rows": [{"bytes": 1_500_000_000, "port": 443, "c2s": 2000}], "others_bytes": 5_000, "flag": True}
    )
    assert (
        out["rows"][0]["bytes_text"] == "1.5 GB"
        and out["rows"][0]["c2s_text"] == "2.0 KB"
        and out["others_bytes_text"] == "5.0 KB"
    )
    assert "port_text" not in out["rows"][0] and "flag_text" not in out


def test_aggregate_built_before_the_window_settled_is_stale_and_rebuilt_under_a_version(estates):
    from datetime import timedelta

    from network_flow_insight.tools import build_aggregate

    settled_at = datetime(2026, 3, 9, 1, 0, tzinfo=UTC)  # end of 2026-03-08 plus 60 minutes

    class G(FakeGlue):
        def __init__(self, created):
            super().__init__(_glue_table(["day"]))
            self.created = created

        def get_table(self, DatabaseName, Name):  # noqa: N803
            return {"Table": {"CreateTime": self.created, "StorageDescriptor": {"Location": "s3://r/old/"}}}

    early = build_aggregate.find_aggregate(G(settled_at - timedelta(minutes=5)), "db", "2026-03-02", "2026-03-08", source="db.flow")
    assert early["stale"] is True and early["reused"] is False
    late = build_aggregate.find_aggregate(G(settled_at), "db", "2026-03-02", "2026-03-08", source="db.flow")
    assert late["reused"] is True and not late.get("stale")
    assert not build_aggregate.window_settled("2026-03-08", 60, settled_at - timedelta(seconds=1))
    assert build_aggregate.window_settled("2026-03-08", 60, settled_at)

    fake = FakeAthena()
    eng = GaugedEngine(
        AthenaEngine(fake, "wg", "s3://r/", "nfi_agent", enforce_output=False), CostGauge(5.0, 5.0, 50.0)
    )
    inv = s3layout.walk(LocalS3(estates["full"].s3_root), "b", "2026-03-02", "2026-03-08")
    scheme = TableScheme("db", "flow", tuple(DEFAULT_FIELDS))
    out = build_aggregate.build_aggregate(
        scheme, "2026-03-02", "2026-03-08", eng, inv, agg_database="nfi_agent",
        results_prefix="s3://r/", version="20260308120000",
    )
    from network_flow_insight.core.aggregate import aggregate_table_name, source_tag

    versioned = aggregate_table_name("2026-03-02", "2026-03-08", "db.flow") + "_b20260308120000"
    assert out["aggregate_table"] == versioned
    assert out["location"] == (
        f"s3://r/nfi/aggregate/source={source_tag('db.flow')}/window=2026-03-02_2026-03-08/build=20260308120000/"
    )
    assert next(iter(fake.sql.values())).startswith(f"CREATE TABLE nfi_agent.{versioned} ")
    with pytest.raises(ValueError):
        build_aggregate.build_aggregate(
            scheme, "2026-03-02", "2026-03-08", eng, inv, agg_database="nfi_agent",
            results_prefix="s3://r/", version="x/../y",
        )


def test_fresh_versioned_build_is_read_from_where_glue_says_it_is():
    """A workgroup that enforces its output location ignores the CTAS location; read the table's real one."""
    from types import SimpleNamespace

    from network_flow_insight.analysis import Analysis

    reads, asked = [], []

    def find(first, last, table=None):
        asked.append(table)
        return {"aggregate_table": table, "location": "s3://enforced/tables/abc/", "reused": True}

    stub = SimpleNamespace(b=SimpleNamespace(read_parquet_fn=lambda loc: reads.append(loc) or [], find_aggregate_fn=find))
    build = {"reused": False, "location": "s3://r/nfi/aggregate/window=x/build=1/"}
    Analysis._rows_for(stub, "nfi_agg_20260302_20260308_b1", "2026-03-02", "2026-03-08", build)
    assert asked == ["nfi_agg_20260302_20260308_b1"]
    assert reads == ["s3://enforced/tables/abc/"]


def _hive_parquet_tree(root, days=("2026-03-01", "2026-03-02"), hours=("05", "06")):
    """A delivered Parquet, Hive-compatible, hourly layout as AWS writes it (key names copied from a real bucket)."""
    acct, region = "123456789012", "eu-west-2"
    table = pa.table({"version": [5], "account_id": [acct], "interface_id": ["eni-0example"], "srcaddr": ["10.0.0.1"],
                      "dstaddr": ["198.51.100.1"], "bytes": [100], "pkt_srcaddr": ["10.0.0.1"], "traffic_path": [1]})
    for d in days:
        y, m, dd = d.split("-")
        for h in hours:
            p = (root / "AWSLogs" / f"aws-account-id={acct}" / "aws-service=vpcflowlogs" / f"aws-region={region}"
                 / f"year={y}" / f"month={m}" / f"day={dd}" / f"hour={h}")
            p.mkdir(parents=True, exist_ok=True)
            pq.write_table(table, p / f"{acct}_vpcflowlogs_{region}_fl-0example_{y}{m}{dd}T{h}00Z_abcd1234.log.parquet")


def test_discover_and_detect_fields_on_hive_parquet_hourly(tmp_path):
    _hive_parquet_tree(tmp_path)
    s3 = LocalS3(tmp_path)
    inv = s3layout.discover(s3, "b")
    assert inv.accounts == {"123456789012"} and inv.regions_by_account == {"123456789012": {"eu-west-2"}}
    assert inv.days == ["2026-03-01", "2026-03-02"]
    assert inv.layout == "hive" and inv.file_format == "parquet" and inv.hourly
    assert "/day=02/hour=" in inv.sample_key and inv.sample_key.endswith(".log.parquet")
    assert s3layout.detect_fields(s3, inv)[:3] == ("version", "account_id", "interface_id")
    walked = s3layout.walk(s3, "b", "2026-03-01", "2026-03-02")
    assert walked.bytes_for() > 0 and walked.layout == "hive" and walked.hourly


def test_aggregates_of_different_flow_log_tables_never_share_a_name_or_location(estates):
    """Seen on real data: two flow-log tables over the same window collided (ALREADY_EXISTS), and once settled one
    would have reused the other's aggregate."""
    from network_flow_insight.core.aggregate import aggregate_table_name
    from network_flow_insight.tools import build_aggregate

    a = aggregate_table_name("2026-03-02", "2026-03-08", "flowdb.text_logs")
    b = aggregate_table_name("2026-03-02", "2026-03-08", "flowdb.parquet_logs")
    assert a != b and a.startswith("nfi_agg_") and a.endswith("_20260302_20260308")
    assert a == aggregate_table_name("2026-03-02", "2026-03-08", "FlowDB.Text_Logs")  # identifiers are case-insensitive
    inv = s3layout.walk(LocalS3(estates["full"].s3_root), "b", "2026-03-02", "2026-03-08")
    outs = []
    for t in ("text_logs", "parquet_logs"):
        fake = FakeAthena()
        eng = GaugedEngine(AthenaEngine(fake, "wg", "s3://r/", "nfi_agent", enforce_output=False), CostGauge(5.0, 5.0, 50.0))
        outs.append(build_aggregate.build_aggregate(
            TableScheme("flowdb", t, tuple(DEFAULT_FIELDS)), "2026-03-02", "2026-03-08", eng, inv,
            agg_database="nfi_agent", results_prefix="s3://r/", version="20260308120000",
        ))
    assert outs[0]["aggregate_table"] != outs[1]["aggregate_table"]
    assert outs[0]["location"] != outs[1]["location"]


def test_analysis_looks_up_the_aggregate_of_its_own_flow_log_table(make_analysis):
    from network_flow_insight.core.aggregate import aggregate_table_name

    a, _ = make_analysis("full")
    asked = []
    a.b.find_aggregate_fn = lambda first, last, table=None: asked.append(table)
    a.window_data("2026-03-02", "2026-03-08")
    assert asked and asked[0] == aggregate_table_name("2026-03-02", "2026-03-08", a.b.scheme.qualified)
