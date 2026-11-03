# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Resource lookup and health for intent-named resources (checks 4 and 6)."""

import pytest

from drift_core.checks import EvaluationContext
from drift_core.checks.resources import lookup, vif_health
from tests.fixtures import snapshots as fx


def ctx(regions=None, cloudwan=None, not_evaluated=()):
    return EvaluationContext(cloudwan=cloudwan, regions=regions or {}, regions_not_evaluated=frozenset(not_evaluated))


def test_vif_health():
    assert vif_health(fx.vif("dxvif-1")) == (True, "available, 1/1 BGP peer(s) up")
    assert vif_health(fx.vif("dxvif-1", state="down"))[1] == "VIF state down"
    assert vif_health(fx.vif("dxvif-1", bgp="down")) == (False, "no BGP peer up")


def test_tgw_attachment_lookup():
    r = fx.clean_region()
    r["attachments"][1]["state"] = "deleting"
    c = ctx({"eu-central-1": r})
    assert lookup("tgw-attach-0prd", c).healthy is True
    dev = lookup("TGW-ATTACH-0DEV", c)
    assert dev.found and not dev.healthy and dev.detail == "attachment deleting"
    gone = lookup("tgw-attach-0zzz", c)
    assert not gone.found and not gone.unverifiable
    assert lookup("tgw-attach-0zzz", ctx({"eu-central-1": r}, not_evaluated=("eu-west-1",))).unverifiable


def test_cloudwan_attachment_lookup():
    cw = fx.clean_cloudwan()
    cw["attachments"][1]["state"] = "PENDING_ATTACHMENT_ACCEPTANCE"
    c = ctx(cloudwan=cw)
    assert lookup("attachment-0prd", c).healthy and lookup("attachment-0prd", c).region == "eu-central-1"
    assert not lookup("attachment-0dev", c).healthy
    assert lookup("attachment-0zzz", c).found is False and lookup("attachment-0zzz", c).unverifiable is False
    assert lookup("attachment-0prd", ctx()).unverifiable is True


@pytest.mark.parametrize("state,up,healthy", [("available", 2, True), ("available", 0, False), ("pending", 1, False)])
def test_vpn_lookup(state, up, healthy):
    r = fx.region()
    r["vpn_connections"] = [{"vpn_id": "vpn-01", "state": state, "tunnels": 2, "tunnels_up": up}]
    assert lookup("vpn-01", ctx({"eu-central-1": r})).healthy is healthy
    assert lookup("vpn-02", ctx({"eu-central-1": r})).found is False


def test_dx_gateway_lookup():
    r = fx.region(associations=[{"association_id": "a", "dxgw_id": "GW-1", "state": "associating"}])
    s = lookup("gw-1", ctx({"eu-central-1": r}))
    assert s.found and not s.healthy and s.region is None
    assert not lookup("gw-2", ctx({"eu-central-1": r})).found
