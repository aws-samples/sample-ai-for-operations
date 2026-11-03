# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""webhook.py: signature, URL posture, priority, batching, description block, POST errors (tasks.md 3.1)."""

import base64
import datetime as dt
import hashlib
import hmac
import json
import urllib.error
import urllib.request

import pytest

from drift_core import webhook as wh
from drift_core.finding import finding_id

CTX = wh.RunContext(run_id="2026-10-13T05:00:00Z-a1b2c3d4", account_id="123456789012",
                    started_at="2026-10-13T05:00:00Z", lookback_from="2026-10-12T05:00:00Z")
URL = "https://event-ai.us-east-1.api.aws/webhook/generic/abc123-DEF_456"


def f(kind, *identity, region="eu-central-1", severity="drift", **context):
    return {"finding_id": finding_id(kind, region, identity), "kind": kind, "check": "check3", "region": region,
            "severity": severity, "identity": list(identity), "expected": {}, "observed": {"state": "x"},
            "context": context, "message": f"{kind} on {' '.join(identity)}"}


# --- Signature: the docs' cURL example -------------------------------------------------------------

# The webhook docs' "Version 1 (HMAC authentication) - cURL" script with its placeholders fixed:
# SECRET=YOUR_WEBHOOK_SECRET, TIMESTAMP=2025-11-23T18:00:00.000Z, INCIDENT_ID=test-alert-1763920800.
# PAYLOAD is the heredoc ($(...) strips the trailing newline); the signature is
#   echo -n "${TIMESTAMP}:${PAYLOAD}" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64
# EXPECTED was produced by running exactly that pipeline with openssl.
DOC_SECRET = "YOUR_WEBHOOK_SECRET"  # nosec B105 -- the literal placeholder text from the docs' cURL example, not a secret
DOC_TIMESTAMP = "2025-11-23T18:00:00.000Z"
DOC_PAYLOAD = (
    "{\n"
    '"eventType": "incident",\n'
    '"incidentId": "test-alert-1763920800",\n'
    '"action": "created",\n'
    '"priority": "HIGH",\n'
    '"title": "Test Alert",\n'
    '"description": "Test alert description",\n'
    '"service": "TestService",\n'
    '"timestamp": "2025-11-23T18:00:00.000Z"\n'
    "}"
)
DOC_EXPECTED = "oiujqV3baxoWelEE+5U3F7VOREfr9VHRdk+wTXNryZY="


def test_signature_matches_docs_curl_example():
    assert wh.sign(DOC_SECRET, DOC_TIMESTAMP, DOC_PAYLOAD) == DOC_EXPECTED


def test_signed_headers_use_documented_names():
    headers = wh.signed_headers(DOC_SECRET, DOC_TIMESTAMP, DOC_PAYLOAD)
    assert headers == {"Content-Type": "application/json", "x-amzn-event-timestamp": DOC_TIMESTAMP,
                       "x-amzn-event-signature": DOC_EXPECTED}


def test_timestamp_format():
    moment = dt.datetime(2026, 10, 13, 7, 0, 1, 234567, tzinfo=dt.timezone(dt.timedelta(hours=2)))
    assert wh.timestamp(moment) == "2026-10-13T05:00:01.234Z"


def test_body_fields_and_signature_over_exact_body():
    batch = wh.make_batches([f("blackhole-route", "10.0.0.0/8", "tgw-rtb-1")], CTX, 25, 12288)[0].to_dict()
    body = wh.build_body(batch, CTX.run_id, "2026-10-13T05:00:01.000Z")
    payload = json.loads(body)
    assert payload["eventType"] == "incident" and payload["action"] == "created"
    assert payload["incidentId"] == f"nrdc-{CTX.run_id}-1" and payload["priority"] == "HIGH"
    assert payload["service"] == "network-routing-drift-checker"
    assert payload["data"] == {"run_id": CTX.run_id, "batch": 1, "batches": 1}
    expected = base64.b64encode(hmac.new(b"k" * 32, f"2026-10-13T05:00:01.000Z:{body}".encode(),
                                         hashlib.sha256).digest()).decode()
    assert wh.sign("k" * 32, "2026-10-13T05:00:01.000Z", body) == expected


# --- URL ---------------------------------------------------------------------------------------------

def test_valid_url_and_region():
    assert wh.validate_url(URL) == URL
    assert wh.webhook_region(URL) == "us-east-1"
    assert wh.webhook_region("https://event-ai.ap-southeast-2.api.aws/webhook/generic/x") == "ap-southeast-2"


@pytest.mark.parametrize("url", [
    "http://event-ai.us-east-1.api.aws/webhook/generic/abc",
    "https://event-ai.us-east-1.api.aws/webhook/generic/abc/",
    "https://event-ai.us-east-1.api.aws/webhook/generic/abc?x=1",
    "https://event-ai.us-east-1.api.aws:8443/webhook/generic/abc",
    "https://user@event-ai.us-east-1.api.aws/webhook/generic/abc",
    "https://event-ai.us-east-1.api.aws.evil.example/webhook/generic/abc",
    "https://evil.example/webhook/generic/abc",
    "https://event-ai.us-east-1.api.aws/webhook/other/abc",
    "file:///etc/passwd",
    "",
    None,
])
def test_invalid_urls_rejected_without_echo(url):
    with pytest.raises(wh.WebhookConfigError) as exc:
        wh.validate_url(url)
    assert "abc" not in str(exc.value)
    with pytest.raises(wh.WebhookConfigError):
        wh.webhook_region(url)


# --- Priority and selection ----------------------------------------------------------------------------

def test_priority_rule():
    assert wh.priority([f("tgw-prefix-leak", "tgw-rtb-1", "10.0.0.0/8", "tgw-attach-1")]) == "MEDIUM"
    for kind in ("blackhole-route", "redundancy-bgp-down", "redundancy-member-down", "redundancy-pair-down",
                 "redundancy-member-missing"):
        assert wh.priority([f(kind, "x-1")]) == "HIGH"
    assert wh.priority([f("limit-threshold", "tgw-total-routes", "tgw-1", limit_name="tgw-total-routes")]) == "MEDIUM"
    assert wh.priority([f("limit-threshold", "x", "dxvif-1", limit_name="dx-onprem-to-aws-per-bgp-session")]) == "HIGH"


def test_only_new_drift_findings_are_investigated():
    items = [f("blackhole-route", "a"), f("untagged-attachment", "b", severity="informational"),
             f("region-not-evaluated", "c", severity="system")]
    assert [i["kind"] for i in wh.investigable(items)] == ["blackhole-route"]


def test_kind_families():
    assert [wh.kind_family(k) for k in ("blackhole-route", "redundancy-pair-down", "cloudwan-prefix-leak",
                                        "tgw-wrong-route-table", "limit-threshold", "hybrid-path-backup-absent",
                                        "untagged-route-table")] == list(wh.KIND_ORDER)


# --- Batching (D§6.1) --------------------------------------------------------------------------------

def _ids(batch):
    return set(batch.finding_ids)


def test_resource_affinity_keeps_shared_resources_together():
    rtb_a = [f("blackhole-route", f"10.{i}.0.0/16", "tgw-rtb-aaa") for i in range(3)]
    rtb_b = [f("blackhole-route", f"10.{i}.0.0/16", "tgw-rtb-bbb") for i in range(3)]
    vif = [f("redundancy-member-down", "dxvif-1", pair="site-a"), f("redundancy-pair-down", "site-a", pair="site-a"),
           f("redundancy-bgp-down", "dxvif-1", "peer-1", pair="site-a")]
    batches = wh.make_batches(rtb_a + vif + rtb_b, CTX, max_findings=4, max_description_bytes=12288)
    groups = [{x["finding_id"] for x in rtb_a}, {x["finding_id"] for x in rtb_b}, {x["finding_id"] for x in vif}]
    for group in groups:
        assert any(group <= _ids(b) for b in batches), "a resource group was split across batches"
    assert all(len(b.finding_ids) <= 4 for b in batches) and len(batches) == 3


def test_leak_findings_connect_through_source_attachment():
    leaks = [f("tgw-prefix-leak", "tgw-rtb-1", "10.0.0.0/16", "tgw-attach-x"),
             f("tgw-prefix-leak", "tgw-rtb-2", "10.0.0.0/16", "tgw-attach-x"),
             f("tgw-prefix-leak", "tgw-rtb-2", "10.1.0.0/16", "tgw-attach-y")]
    groups = wh.affinity_groups(leaks + [f("blackhole-route", "10.9.0.0/16", "tgw-rtb-9")])
    assert [len(g) for g in groups] == [3, 1]


def test_cloudwan_table_ref_is_one_table_not_whole_core_network():
    a = f("blackhole-route", "core-network-0abc/prod/eu-central-1", "10.0.0.0/16")
    b = f("blackhole-route", "core-network-0abc/dev/eu-west-1", "10.1.0.0/16")
    assert len(wh.affinity_groups([a, b])) == 2


def test_count_cap_splits_large_groups_and_multiple_batches():
    many = [f("blackhole-route", f"10.{i}.0.0/16", "tgw-rtb-aaa") for i in range(60)]
    batches = wh.make_batches(many, CTX, max_findings=25, max_description_bytes=100_000)
    assert [len(b.finding_ids) for b in batches] == [25, 25, 10]
    assert [b.batch_n for b in batches] == [1, 2, 3] and {b.batches for b in batches} == {3}
    assert sorted(i for b in batches for i in b.finding_ids) == sorted(x["finding_id"] for x in many)
    assert len({b.incident_id for b in batches}) == 3


def test_description_size_cap():
    big = [f("blackhole-route", f"10.{i}.0.0/16", f"tgw-rtb-{i:03d}", note="x" * 600) for i in range(25)]
    batches = wh.make_batches(big, CTX, max_findings=25, max_description_bytes=4096)
    assert len(batches) > 1
    assert all(len(b.description.encode()) <= 4096 for b in batches)
    assert sum(len(b.finding_ids) for b in batches) == 25


def test_single_oversized_finding_is_truncated_to_fit():
    huge = f("blackhole-route", "10.0.0.0/16", "tgw-rtb-1", **{f"k{i}": "v" * 700 for i in range(20)})
    huge["message"] = "m" * 5000
    (batch,) = wh.make_batches([huge], CTX, max_findings=25, max_description_bytes=2048)
    assert len(batch.description.encode()) <= 2048 and "truncated" in batch.description


def test_bad_limits_rejected():
    with pytest.raises(ValueError):
        wh.make_batches([], CTX, max_findings=0, max_description_bytes=12288)
    with pytest.raises(ValueError):
        wh.make_batches([], CTX, max_findings=25, max_description_bytes=600)


def test_description_block_shape_and_tag_line():
    items = [f("tgw-prefix-leak", "tgw-rtb-1", "10.0.0.0/16", "tgw-attach-x"), f("blackhole-route", "10.0.0.0/8",
                                                                                  "tgw-rtb-2")]
    (batch,) = wh.make_batches(items, CTX, 25, 12288)
    lines = batch.description.splitlines()
    assert lines[0] == f"[INVESTIGATION_ID:nrdc-{CTX.run_id}-1]"
    assert lines[1].startswith("NETWORK ROUTING DRIFT — NEW FINDINGS (run ")
    assert "Account 123456789012. Batch 1 of 1." in lines[2]
    assert lines[-1] == f"Lookback window for change events: {CTX.lookback_from} → {CTX.started_at}."
    # blackhole sorts before leak (kind order), numbered from 1
    assert any(line.startswith("[1] id=") and "kind=blackhole-route" in line for line in lines)
    assert any(line.startswith("[2] id=") and "kind=tgw-prefix-leak" in line for line in lines)
    assert batch.title == "Network routing drift: 2 new findings (1 blackhole-route, 1 tgw-prefix-leak)"
    assert batch.finding_kinds == {i["finding_id"]: i["kind"] for i in items}


def test_batching_is_deterministic():
    items = [f("blackhole-route", f"10.{i}.0.0/16", f"tgw-rtb-{i % 3}") for i in range(10)]
    first = [b.to_dict() for b in wh.make_batches(items, CTX, 4, 12288)]
    second = [b.to_dict() for b in wh.make_batches(list(reversed(items)), CTX, 4, 12288)]
    assert first == second


# --- POST (no network: the opener is replaced) ------------------------------------------------------

class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, outcome):
        self.outcome, self.requests, self.handlers = outcome, [], []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return _Response()


@pytest.fixture
def opener(monkeypatch):
    holder = {}

    def install(outcome):
        op = _Opener(outcome)

        def build_opener(*handlers):
            op.handlers = handlers
            return op
        monkeypatch.setattr(urllib.request, "build_opener", build_opener)
        holder["op"] = op
        return op
    return install


def test_post_success_sends_signed_request_without_redirects(opener):
    op = opener(None)
    headers = wh.signed_headers("s" * 32, "2026-10-13T05:00:01.000Z", "{}")
    assert wh.post(URL, "{}", headers, timeout=7) == 200
    request, timeout = op.requests[0]
    assert request.get_method() == "POST" and request.full_url == URL and timeout == 7
    assert request.get_header("X-amzn-event-signature") == headers["x-amzn-event-signature"]
    assert any(isinstance(h, urllib.request.HTTPRedirectHandler) for h in op.handlers)
    assert op.handlers[0].redirect_request(None, None, 302, "", {}, "http://evil.example/") is None


@pytest.mark.parametrize("outcome, error", [
    (urllib.error.HTTPError(URL, 500, "boom", {}, None), wh.WebhookServerError),
    (urllib.error.HTTPError(URL, 503, "boom", {}, None), wh.WebhookServerError),
    (urllib.error.HTTPError(URL, 403, "denied", {}, None), wh.WebhookClientError),
    (urllib.error.HTTPError(URL, 302, "redirect", {}, None), wh.WebhookClientError),
    (TimeoutError("timed out"), wh.WebhookTimeout),
    (urllib.error.URLError(TimeoutError("timed out")), wh.WebhookTimeout),
    (urllib.error.URLError(ConnectionRefusedError("no")), wh.WebhookTransportError),
    (ConnectionResetError("reset"), wh.WebhookTransportError),
])
def test_post_errors_are_classified_and_never_echo_url(opener, outcome, error):
    opener(outcome)
    with pytest.raises(error) as exc:
        wh.post(URL, "{}", {}, timeout=1)
    assert isinstance(exc.value, wh.WebhookError)
    assert URL not in str(exc.value) and exc.value.__cause__ is None


def test_post_refuses_invalid_url_before_any_io(opener):
    op = opener(None)
    with pytest.raises(wh.WebhookConfigError):
        wh.post("http://event-ai.us-east-1.api.aws/webhook/generic/abc", "{}", {}, timeout=1)
    assert op.requests == []
