# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The synthetic estate: inventory, address plan, AWS ranges, prices, traffic templates.

Everything here is invented. Account IDs are from the documentation range, public addresses are from
RFC 5737 documentation ranges or the 198.18.0.0/15 benchmarking block, and "AWS" ranges are made up
from that block so that nothing here can match a real address.
"""

from __future__ import annotations

from typing import Any

REGION = "eu-west-2"
OTHER_REGION = "us-east-1"
ACCT_A = "123456789012"
ACCT_B = "123456789013"

# Two equal windows, one week each. 2026-03-02 is a Monday.
WINDOW_A = ("2026-02-23", "2026-03-01")  # previous window
WINDOW_B = ("2026-03-02", "2026-03-08")  # current window
SKIPDATA_DAY = "2026-03-04"
SKIPDATA_ENI = "eni-0w1"
SKIPDATA_RECORDS = 20
NODATA_RECORDS = 10

NAT_IPS = ("10.10.0.10", "10.10.0.11")  # primary and secondary private address of nat-1
NAT_PUBLIC = "192.0.2.10"

# ip -> (interface id, account id)
WORKLOADS = {
    "10.10.1.5": ("eni-0w1", ACCT_A),
    "10.10.1.6": ("eni-0w5", ACCT_A),
    "10.10.2.7": ("eni-0w2", ACCT_A),
    "10.10.3.9": ("eni-0w3", ACCT_A),
    "10.20.1.4": ("eni-0w4", ACCT_B),
}
ENDPOINT_ENIS = {"10.10.1.200": "eni-0ep1", "10.10.2.200": "eni-0ep2"}
NAT_ENI = "eni-0nat1"

INTERNET = {
    "a": "203.0.113.50",
    "b": "203.0.113.60",
    "new": "240.0.2.99",
    "c": "198.51.100.7",
    "gone": "240.0.1.77",
    "attacker": "198.51.100.200",
}
S3_LOCAL = ("198.18.0.10", "198.18.0.20", "198.18.0.30")
S3_REMOTE_REGION = "198.18.1.10"
DDB_PUBLIC = ("198.18.2.10", "198.18.2.11")
EC2_ONLY = "198.18.16.5"
AMAZON_ONLY = "198.18.32.5"
ONPREM = "10.200.5.5"
REMOTE_VPC_HOST = "10.30.0.5"


def ip_ranges_document() -> dict[str, Any]:
    def p(cidr: str, region: str, service: str) -> dict:
        return {"ip_prefix": cidr, "region": region, "service": service, "network_border_group": region}

    return {
        "syncToken": "1772000000",
        "createDate": "2026-02-01-00-00-00",
        "prefixes": [
            p("198.18.0.0/15", "GLOBAL", "AMAZON"),
            p("198.18.0.0/24", REGION, "AMAZON"),
            p("198.18.0.0/24", REGION, "S3"),
            p("198.18.1.0/24", OTHER_REGION, "AMAZON"),
            p("198.18.1.0/24", OTHER_REGION, "S3"),
            p("198.18.2.0/24", REGION, "AMAZON"),
            p("198.18.2.0/24", REGION, "DYNAMODB"),
            p("198.18.16.0/20", REGION, "AMAZON"),
            p("198.18.16.0/20", REGION, "EC2"),
            p("198.18.32.0/24", REGION, "AMAZON"),
        ],
        "ipv6_prefixes": [],
    }


def inventory_document() -> dict[str, Any]:
    app_routes = [
        {"destination": "10.10.0.0/16", "target_type": "local", "target_id": "local"},
        {"destination": "0.0.0.0/0", "target_type": "nat-gateway", "target_id": "nat-0001"},
        {"destination": "10.20.0.0/16", "target_type": "transit-gateway", "target_id": "tgw-0001"},
        {"destination": "10.30.0.0/16", "target_type": "transit-gateway", "target_id": "tgw-0001"},
        {"destination": "10.200.0.0/16", "target_type": "vgw", "target_id": "vgw-0001"},
    ]
    gw_s3 = {"prefix_list_id": "pl-s3", "target_type": "gateway-endpoint", "target_id": "vpce-s3"}

    def eni(
        i: str,
        acct: str,
        subnet: str,
        az: str,
        role: str,
        ips: list[str],
        vpc: str = "vpc-0a01",
        desc: str = "",
    ) -> dict:
        return {
            "id": i,
            "account_id": acct,
            "region": REGION,
            "vpc_id": vpc,
            "subnet_id": subnet,
            "az": az,
            "role": role,
            "private_ips": ips,
            "description": desc,
        }

    return {
        "schema_version": 1,
        "source": "file",
        "collected_at": "2026-03-09T00:00:00Z",
        "vpcs": [
            {"id": "vpc-0a01", "account_id": ACCT_A, "region": REGION, "cidrs": ["10.10.0.0/16"]},
            {"id": "vpc-0b02", "account_id": ACCT_B, "region": REGION, "cidrs": ["10.20.0.0/16"]},
            {"id": "vpc-0c03", "account_id": ACCT_A, "region": OTHER_REGION, "cidrs": ["10.30.0.0/16"]},
        ],
        "subnets": [
            {
                "id": "subnet-pub",
                "vpc_id": "vpc-0a01",
                "account_id": ACCT_A,
                "region": REGION,
                "az": "euw2-az1",
                "cidr": "10.10.0.0/24",
                "route_table_id": "rt-pub",
            },
            {
                "id": "subnet-app-a",
                "vpc_id": "vpc-0a01",
                "account_id": ACCT_A,
                "region": REGION,
                "az": "euw2-az1",
                "cidr": "10.10.1.0/24",
                "route_table_id": "rt-app-a",
            },
            {
                "id": "subnet-app-b",
                "vpc_id": "vpc-0a01",
                "account_id": ACCT_A,
                "region": REGION,
                "az": "euw2-az2",
                "cidr": "10.10.2.0/24",
                "route_table_id": "rt-app-b",
            },
            {
                "id": "subnet-data",
                "vpc_id": "vpc-0a01",
                "account_id": ACCT_A,
                "region": REGION,
                "az": "euw2-az1",
                "cidr": "10.10.3.0/24",
                "route_table_id": "rt-data",
            },
            {
                "id": "subnet-b-app",
                "vpc_id": "vpc-0b02",
                "account_id": ACCT_B,
                "region": REGION,
                "az": "euw2-az1",
                "cidr": "10.20.1.0/24",
                "route_table_id": "rt-b-app",
            },
        ],
        "route_tables": [
            {
                "id": "rt-pub",
                "vpc_id": "vpc-0a01",
                "main": False,
                "routes": [
                    {"destination": "10.10.0.0/16", "target_type": "local", "target_id": "local"},
                    {"destination": "0.0.0.0/0", "target_type": "internet-gateway", "target_id": "igw-0001"},
                ],
            },
            # app-a has no gateway-endpoint route: planted for E6.
            {"id": "rt-app-a", "vpc_id": "vpc-0a01", "main": False, "routes": list(app_routes)},
            {"id": "rt-app-b", "vpc_id": "vpc-0a01", "main": False, "routes": [*app_routes, gw_s3]},
            {"id": "rt-data", "vpc_id": "vpc-0a01", "main": True, "routes": [*app_routes, gw_s3]},
            {
                "id": "rt-b-app",
                "vpc_id": "vpc-0b02",
                "main": True,
                "routes": [
                    {"destination": "10.20.0.0/16", "target_type": "local", "target_id": "local"},
                    {
                        "destination": "10.10.0.0/16",
                        "target_type": "transit-gateway",
                        "target_id": "tgw-0001",
                    },
                    {"destination": "0.0.0.0/0", "target_type": "internet-gateway", "target_id": "igw-0002"},
                ],
            },
        ],
        "interfaces": [
            eni("eni-0w1", ACCT_A, "subnet-app-a", "euw2-az1", "workload", ["10.10.1.5"]),
            eni("eni-0w5", ACCT_A, "subnet-app-a", "euw2-az1", "workload", ["10.10.1.6"]),
            eni("eni-0w2", ACCT_A, "subnet-app-b", "euw2-az2", "workload", ["10.10.2.7"]),
            eni("eni-0w3", ACCT_A, "subnet-data", "euw2-az1", "workload", ["10.10.3.9"]),
            eni("eni-0w4", ACCT_B, "subnet-b-app", "euw2-az1", "workload", ["10.20.1.4"], vpc="vpc-0b02"),
            eni(
                NAT_ENI,
                ACCT_A,
                "subnet-pub",
                "euw2-az1",
                "nat-gateway",
                list(NAT_IPS),
                desc="Interface for NAT Gateway nat-0001",
            ),
            eni(
                "eni-0ep1",
                ACCT_A,
                "subnet-app-a",
                "euw2-az1",
                "interface-endpoint",
                ["10.10.1.200"],
                desc="VPC Endpoint Interface vpce-ddb",
            ),
            eni(
                "eni-0ep2",
                ACCT_A,
                "subnet-app-b",
                "euw2-az2",
                "interface-endpoint",
                ["10.10.2.200"],
                desc="VPC Endpoint Interface vpce-ddb",
            ),
        ],
        "nat_gateways": [
            {
                "id": "nat-0001",
                "vpc_id": "vpc-0a01",
                "subnet_id": "subnet-pub",
                "interface_ids": [NAT_ENI],
                "private_ips": list(NAT_IPS),
                "public_ips": [NAT_PUBLIC],
            },
        ],
        "endpoints": [
            {
                "id": "vpce-s3",
                "vpc_id": "vpc-0a01",
                "type": "Gateway",
                "service_name": f"com.amazonaws.{REGION}.s3",
                "subnet_ids": [],
                "interface_ids": [],
                "private_dns": False,
            },
            {
                "id": "vpce-ddb",
                "vpc_id": "vpc-0a01",
                "type": "Interface",
                "service_name": f"com.amazonaws.{REGION}.dynamodb",
                "subnet_ids": ["subnet-app-a", "subnet-app-b"],
                "interface_ids": ["eni-0ep1", "eni-0ep2"],
                "private_dns": True,
            },
        ],
        "prefix_lists": [
            {"id": "pl-s3", "name": f"com.amazonaws.{REGION}.s3", "cidrs": ["198.18.0.0/24"]},
        ],
        "tgw_attachments": [
            {
                "id": "tgw-attach-1",
                "transit_gateway_id": "tgw-0001",
                "vpc_id": "vpc-0a01",
                "resource_type": "vpc",
                "interface_ids": [],
            },
        ],
    }


def prices_document() -> dict[str, Any]:
    """Synthetic rate table in the shape ``get_prices`` returns. Not real prices."""
    return {
        "region": REGION,
        "currency": "USD",
        "source": "synthetic-fixture",
        "nat_processing_per_gb": 0.05,
        "interface_endpoint_per_gb": 0.01,
        "gateway_endpoint_per_gb": 0.0,
        "inter_az_per_gb": 0.01,
        "inter_region_per_gb": 0.02,
        "internet_out_per_gb": 0.09,
        "transit_gateway_per_gb": 0.02,
        "athena_per_tb": 5.0,
    }


def intent_document() -> dict[str, Any]:
    return {
        "version": 1,
        "networks": [{"name": "on-prem-dc1", "kind": "on-premises", "cidrs": ["10.200.0.0/16"]}],
    }


def resolver_document() -> dict[str, list[str]]:
    return {AMAZON_ONLY: ["queue.example-service.eu-west-2.amazonaws.com"]}


# Traffic templates. Per-day base bytes; weekday multiplier 1.0, weekend multiplier ``wk``;
# window B multiplied by ``growth``. ``windows`` says which windows contain the exchange.
TEMPLATES: list[dict[str, Any]] = [
    dict(
        id="N1",
        client="10.10.1.5",
        server=INTERNET["a"],
        port=443,
        kind="nat",
        windows="AB",
        c2s=2_000_000,
        s2c=18_000_000,
        hours=[13, 14, 15],
        wk=0.4,
        growth=1.0,
    ),
    dict(
        id="N2",
        client="10.10.2.7",
        server=INTERNET["b"],
        port=443,
        kind="nat",
        windows="AB",
        c2s=1_000_000,
        s2c=9_000_000,
        hours=[9, 10],
        wk=0.4,
        growth=1.5,
    ),
    dict(
        id="N3",
        client="10.10.1.6",
        server=INTERNET["c"],
        port=443,
        kind="nat",
        windows="AB",
        c2s=500_000,
        s2c=4_500_000,
        hours=[2],
        wk=1.0,
        growth=1.0,
    ),
    dict(
        id="N-gone",
        client="10.10.1.6",
        server=INTERNET["gone"],
        port=443,
        kind="nat",
        windows="A",
        c2s=300_000,
        s2c=2_700_000,
        hours=[3],
        wk=1.0,
        growth=1.0,
    ),
    dict(
        id="N-new",
        client="10.10.2.7",
        server=INTERNET["new"],
        port=443,
        kind="nat",
        windows="B",
        c2s=800_000,
        s2c=7_200_000,
        hours=[11],
        wk=1.0,
        growth=1.0,
    ),
    dict(
        id="S3-nat",
        client="10.10.1.5",
        server=S3_LOCAL[0],
        port=443,
        kind="nat",
        windows="AB",
        c2s=3_000_000,
        s2c=27_000_000,
        hours=[10, 11],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="S3-gw2",
        client="10.10.2.7",
        server=S3_LOCAL[1],
        port=443,
        kind="gateway-endpoint",
        windows="AB",
        c2s=4_000_000,
        s2c=36_000_000,
        hours=[10, 11, 12],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="S3-gw3",
        client="10.10.3.9",
        server=S3_LOCAL[2],
        port=443,
        kind="gateway-endpoint",
        windows="AB",
        c2s=1_000_000,
        s2c=9_000_000,
        hours=[4],
        wk=1.0,
        growth=1.0,
    ),
    dict(
        id="S3-xr",
        client="10.10.1.5",
        server=S3_REMOTE_REGION,
        port=443,
        kind="nat",
        windows="AB",
        c2s=600_000,
        s2c=5_400_000,
        hours=[5],
        wk=1.0,
        growth=1.0,
    ),
    dict(
        id="DDB-nat",
        client="10.10.2.7",
        server=DDB_PUBLIC[0],
        port=443,
        kind="nat",
        windows="AB",
        c2s=700_000,
        s2c=6_300_000,
        hours=[9],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="DDB-ep",
        client="10.10.1.5",
        server="10.10.1.200",
        port=443,
        kind="interface-endpoint",
        windows="A",
        c2s=900_000,
        s2c=8_100_000,
        hours=[9],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="DDB-nat-B",
        client="10.10.1.5",
        server=DDB_PUBLIC[1],
        port=443,
        kind="nat",
        windows="B",
        c2s=900_000,
        s2c=8_100_000,
        hours=[9],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="EC2h",
        client="10.10.1.5",
        server=EC2_ONLY,
        port=443,
        kind="nat",
        windows="AB",
        c2s=200_000,
        s2c=1_800_000,
        hours=[16],
        wk=1.0,
        growth=1.0,
    ),
    dict(
        id="AMZ",
        client="10.10.2.7",
        server=AMAZON_ONLY,
        port=443,
        kind="nat",
        windows="AB",
        c2s=100_000,
        s2c=900_000,
        hours=[16],
        wk=1.0,
        growth=1.0,
    ),
    dict(
        id="IV-xaz",
        client="10.10.1.5",
        server="10.10.2.7",
        port=5432,
        kind="intra-vpc",
        windows="AB",
        c2s=5_000_000,
        s2c=45_000_000,
        hours=[9, 10, 11],
        wk=0.3,
        growth=1.0,
    ),
    dict(
        id="AMB",
        client="10.10.1.5",
        server="10.10.1.6",
        port=40000,
        kind="intra-vpc",
        windows="AB",
        c2s=100_000,
        s2c=100_000,
        hours=[20],
        wk=1.0,
        growth=1.0,
        ambiguous=True,
    ),
    dict(
        id="IV-saz",
        client="10.10.1.5",
        server="10.10.1.6",
        port=8080,
        kind="intra-vpc",
        windows="AB",
        c2s=1_000_000,
        s2c=2_000_000,
        hours=[9],
        wk=0.3,
        growth=1.0,
    ),
    dict(
        id="TGW",
        client="10.10.1.5",
        server="10.20.1.4",
        port=443,
        kind="transit-gateway",
        windows="AB",
        c2s=2_000_000,
        s2c=8_000_000,
        hours=[12],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="XR",
        client="10.10.1.5",
        server=REMOTE_VPC_HOST,
        port=443,
        kind="cross-region",
        windows="AB",
        c2s=1_000_000,
        s2c=3_000_000,
        hours=[12],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="ONP",
        client="10.10.3.9",
        server=ONPREM,
        port=1521,
        kind="vgw",
        windows="AB",
        c2s=1_500_000,
        s2c=6_500_000,
        hours=[6],
        wk=0.5,
        growth=1.0,
    ),
    dict(
        id="IGW",
        client="10.20.1.4",
        server=INTERNET["a"],
        port=443,
        kind="internet-gateway",
        windows="AB",
        c2s=400_000,
        s2c=3_600_000,
        hours=[8],
        wk=0.5,
        growth=1.0,
    ),
]
