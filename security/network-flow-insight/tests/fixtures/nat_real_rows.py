# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Record shapes captured from a real NAT gateway network interface (full custom format), sanitised.

Account ID, resource IDs and addresses are replaced with documentation values; the shape of every record
(which address sits in which field, ``flow-direction``, ``traffic-path``, ``pkt-*`` and service fields, port
placement) is exactly as AWS logged it. Rows are in aggregate form (ports normalised: ephemeral stored as 0).

What a NAT gateway interface logs: its private address is source or destination on every record.

======================  ======================  ===========================  ==============  ============
leg                     srcaddr -> dstaddr      pkt-srcaddr -> pkt-dstaddr   flow-direction  traffic-path
======================  ======================  ===========================  ==============  ============
workload side, out      workload -> NAT         workload -> remote           ingress         -
internet side, out      NAT -> remote           NAT -> remote                egress          8
internet side, return   remote -> NAT           remote -> NAT                ingress         -
workload side, return   NAT -> workload         remote -> workload           egress          1
======================  ======================  ===========================  ==============  ============
"""

from __future__ import annotations

ACCOUNT = "123456789012"
REGION = "eu-west-2"
VPC = "vpc-0example0000001"
NAT_ID = "nat-0example0000001"
NAT_ENI = "eni-0example00000nat"
NAT_SUBNET = "subnet-0example0public"
NAT_IP = "10.0.0.43"
WL_A, WL_A_ENI, WL_A_SUBNET = "10.0.1.216", "eni-0example0000wla", "subnet-0example0priva"
WL_B, WL_B_ENI, WL_B_SUBNET = "10.0.2.132", "eni-0example0000wlb", "subnet-0example0privb"
S3_REMOTE = "198.51.100.201"  # stands in for an S3 address
NTP_REMOTE = "203.0.113.61"  # stands in for an EC2-hosted NTP server
SCANNER = "192.0.2.68"  # unsolicited inbound to the NAT address

# S3 GET from workload A over NAT (TCP 443); NTP from workload B over NAT (UDP 123).
S3_OUT, S3_IN = 609_862, 242_887_526
NTP_BYTES = 76
SCANNER_BYTES = 52


def _row(iface, subnet, az, src, dst, sport, dport, proto, nbytes, direction, pkt_src, pkt_dst, path, svc_src, svc_dst):
    return {
        "day": "2026-01-15",
        "hour": 14,
        "account_id": ACCOUNT,
        "region": REGION,
        "interface_id": iface,
        "srcaddr": src,
        "dstaddr": dst,
        "pkt_srcaddr": pkt_src,
        "pkt_dstaddr": pkt_dst,
        "srcport": sport,
        "dstport": dport,
        "protocol": proto,
        "action": "ACCEPT",
        "log_status": "OK",
        "flow_direction": direction,
        "traffic_path": path,
        "pkt_src_aws_service": svc_src,
        "pkt_dst_aws_service": svc_dst,
        "vpc_id": VPC,
        "subnet_id": subnet,
        "az_id": az,
        "bytes": nbytes,
        "packets": max(1, nbytes // 1400),
        "records": 1,
    }


def nat_rows() -> list[dict]:
    """The rows logged on the NAT interface for one S3 exchange, one NTP exchange and one scanner probe."""
    n = NAT_ENI
    s, az = NAT_SUBNET, "euw2-az2"
    return [
        # S3 exchange from workload A
        _row(n, s, az, WL_A, NAT_IP, 0, 443, 6, S3_OUT, "ingress", WL_A, S3_REMOTE, None, None, "S3"),
        _row(n, s, az, NAT_IP, S3_REMOTE, 0, 443, 6, S3_OUT, "egress", NAT_IP, S3_REMOTE, 8, None, "S3"),
        _row(n, s, az, S3_REMOTE, NAT_IP, 443, 0, 6, S3_IN, "ingress", S3_REMOTE, NAT_IP, None, "S3", None),
        _row(n, s, az, NAT_IP, WL_A, 443, 0, 6, S3_IN, "egress", S3_REMOTE, WL_A, 1, "S3", None),
        # NTP exchange from workload B
        _row(n, s, az, WL_B, NAT_IP, 0, 123, 17, NTP_BYTES, "ingress", WL_B, NTP_REMOTE, None, None, "EC2"),
        _row(n, s, az, NAT_IP, NTP_REMOTE, 0, 123, 17, NTP_BYTES, "egress", NAT_IP, NTP_REMOTE, 8, None, "EC2"),
        _row(n, s, az, NTP_REMOTE, NAT_IP, 123, 0, 17, NTP_BYTES, "ingress", NTP_REMOTE, NAT_IP, None, "EC2", None),
        _row(n, s, az, NAT_IP, WL_B, 123, 0, 17, NTP_BYTES, "egress", NTP_REMOTE, WL_B, 1, "EC2", None),
        # Unsolicited inbound to the NAT address: accepted on the internet side, never forwarded.
        _row(n, s, az, SCANNER, NAT_IP, 0, 4040, 6, SCANNER_BYTES, "ingress", SCANNER, NAT_IP, None, None, None),
    ]


def workload_rows() -> list[dict]:
    """The same exchanges as seen on the workloads' own interfaces (the remote is the real remote)."""
    return [
        _row(WL_A_ENI, WL_A_SUBNET, "euw2-az2", WL_A, S3_REMOTE, 0, 443, 6, S3_OUT, "egress", WL_A, S3_REMOTE, 1, None, "S3"),
        _row(WL_A_ENI, WL_A_SUBNET, "euw2-az2", S3_REMOTE, WL_A, 443, 0, 6, S3_IN, "ingress", S3_REMOTE, WL_A, None, "S3", None),
        _row(WL_B_ENI, WL_B_SUBNET, "euw2-az3", WL_B, NTP_REMOTE, 0, 123, 17, NTP_BYTES, "egress", WL_B, NTP_REMOTE, 1, None, "EC2"),
        _row(WL_B_ENI, WL_B_SUBNET, "euw2-az3", NTP_REMOTE, WL_B, 123, 0, 17, NTP_BYTES, "ingress", NTP_REMOTE, WL_B, None, "EC2", None),
    ]


def basic(rows: list[dict]) -> list[dict]:
    """The same rows as a default-format (v2) log would give them: no pkt-* or v5 fields."""
    drop = ("pkt_srcaddr", "pkt_dstaddr", "flow_direction", "traffic_path", "pkt_src_aws_service", "pkt_dst_aws_service")
    return [{**r, **{k: None for k in drop}} for r in rows]


# A Transit Gateway attachment interface logs the same way: its own private address is on every record and the
# real peer is only in pkt-*. Workload A fetching from a server in a spoke VPC over the Transit Gateway.
TGW_ENI, TGW_ENI_IP = "eni-0example0000tgw", "10.0.1.183"
SPOKE_SERVER = "10.1.1.161"
TGW_C2S, TGW_S2C = 12_276, 8_051_396


def tgw_workload_rows() -> list[dict]:
    """The same exchange on workload A's own interface: it records the real peer, never the attachment's address."""
    w, s, az = WL_A_ENI, WL_A_SUBNET, "euw2-az2"
    return [
        _row(w, s, az, WL_A, SPOKE_SERVER, 0, 8080, 6, TGW_C2S, "egress", WL_A, SPOKE_SERVER, 1, None, None),
        _row(w, s, az, SPOKE_SERVER, WL_A, 8080, 0, 6, TGW_S2C, "ingress", SPOKE_SERVER, WL_A, None, None, None),
    ] * 3


def tgw_rows() -> list[dict]:
    t, s, az = TGW_ENI, WL_A_SUBNET, "euw2-az2"
    return [
        _row(t, s, az, WL_A, TGW_ENI_IP, 0, 8080, 6, TGW_C2S, "ingress", WL_A, SPOKE_SERVER, None, None, None),
        _row(t, s, az, TGW_ENI_IP, WL_A, 8080, 0, 6, TGW_S2C, "egress", SPOKE_SERVER, WL_A, 1, None, None),
    ] * 3
