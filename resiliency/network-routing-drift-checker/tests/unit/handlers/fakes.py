# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""In-memory S3 and DynamoDB Table fakes for the Phase 3 handler tests (no network, no credentials)."""

import contextlib
import io
import json
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from drift_core.logging_util import get_logger

BUCKET, TABLE = "drift-bucket", "drift-table"
REGION, ACCOUNT, DEVOPS_ACCOUNT = "us-east-1", "111111111111", "222222222222"
FUNCTION_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:nrdc-callback"
SPACE = "as-0123456789abcdef"
RUN_ID = "2026-10-13T05:00:00Z-a1b2c3d4"
WEBHOOK_URL = "https://event-ai.us-east-1.api.aws/webhook/generic/abc123-DEF_456"
SECRET = "hmac-secret-value-0123456789abcdef"  # nosec B105 -- fixed HMAC test vector, not a real secret
SECRET_PARAM = "/nrdc/webhook-secret"  # nosec B105 -- an SSM parameter *name*, not a secret value
HANDLER_LOGGERS = ("investigate", "batch", "merge", "callback", "drift_core.artifacts")


def fid(n):
    return f"f-{n:020x}"


class Context:
    def __init__(self, arn=FUNCTION_ARN):
        self.invoked_function_arn = arn


def real_client(service, region=REGION):
    """A botocore client for Stubber: stubbed responses are validated against the pinned model."""
    return boto3.client(service, region_name=region, aws_access_key_id="x", aws_secret_access_key="x")  # nosec B106 -- placeholder creds for a Stubber-backed client, never makes a real call


def stubbed(service, region=REGION):
    client = real_client(service, region)
    stubber = Stubber(client)
    stubber.activate()
    return client, stubber


class Clients:
    """Stands in for `aws_clients.client`: one pre-built client per service, every request recorded."""

    def __init__(self, **clients):
        self.clients = clients
        self.calls = []

    def __call__(self, service, region=None):
        self.calls.append((service, region))
        if service not in self.clients:
            raise AssertionError(f"unexpected client request: {service}")
        return self.clients[service]

    def services(self):
        return [service for service, _ in self.calls]


@contextlib.contextmanager
def captured_logs(*names):
    """Point the handlers' JSON log handlers at one buffer (they bind sys.stdout at creation)."""
    buffer, previous = io.StringIO(), []
    for name in names or HANDLER_LOGGERS:
        handler = get_logger(name).handlers[0]
        previous.append((handler, handler.stream))
        handler.setStream(buffer)
    try:
        yield buffer
    finally:
        for handler, stream in previous:
            handler.setStream(stream)


def log_lines(buffer):
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


# --- Run fixtures: findings in, investigation results out ---------------------------------------

def finding(n, kind="blackhole-route", env="prod"):
    """A NEW drift finding with its own route table, so batching keeps each one separate."""
    return {"finding_id": fid(n), "check": "tgw-3", "kind": kind, "severity": "drift", "region": REGION,
            "identity": [f"tgw-rtb-{n:04d}", f"10.0.{n}.0/24"], "message": f"route 10.0.{n}.0/24 blackholed",
            "expected": {"state": "active"}, "observed": {"state": "blackhole"}, "context": {"environment": env}}


def seed_run(s3, findings, run_id=RUN_ID):
    s3.put(f"runs/{run_id}/manifest.json", {"run_id": run_id, "started_at": "2026-10-13T05:00:00Z",
                                            "lookback_from": "2026-05-11T05:00:00Z"})
    informational = {"finding_id": fid(999), "severity": "informational", "kind": "note"}
    s3.put(f"runs/{run_id}/diff.json", {"new": [*findings, informational], "known": [], "resolved": []})


def incident(members, rank=1, env="prod", prefixes=1, attachments=0, domains=1, confidence="high", title=None):
    return {
        "rank": rank, "title": title or f"incident {members[0]}", "member_finding_ids": list(members),
        "root_cause_hypothesis": "Route removed by a change", "confidence": confidence,
        "evidence": [{"type": "cloudtrail", "event_id": "e-1", "event_name": "DeleteTransitGatewayRoute",
                      "time": "2026-10-12T10:00:00Z", "actor": "unknown"},
                     {"type": "state", "resource": "tgw-rtb-0001", "observation": "route blackhole"}],
        "actor_identified": False,
        "blast_radius": {"prefixes": prefixes, "attachments": attachments, "domains": domains, "environment": env,
                         "score": 1},
        "stable_for": "P0D",
        "validation_commands": ["aws ec2 search-transit-gateway-routes --transit-gateway-route-table-id tgw-rtb-1"],
    }


def result_doc(batch_n, incidents, unassigned=(), run_id=RUN_ID, url=None):
    doc = {"schema": "nrdc-investigation/v1", "incidentId": f"nrdc-{run_id}-{batch_n}",
           "incidents": incidents, "unassigned_finding_ids": list(unassigned), "notes": "n"}
    if url:
        doc["investigation_url"] = url
    return doc


def fenced(doc, info="nrdc-investigation/v1"):
    body = doc if isinstance(doc, str) else json.dumps(doc)
    return f"Investigation complete.\n\n```{info}\n{body}\n```\n"


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, ContentType=None):  # noqa: N803
        self.objects[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.encode()

    def get_object(self, Bucket, Key):  # noqa: N803
        if (Bucket, Key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def put(self, key, obj):
        self.objects[(BUCKET, key)] = json.dumps(obj).encode()

    def json(self, key):
        return json.loads(self.objects[(BUCKET, key)])


def _ccf():
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")


class FakeTable:
    """Implements exactly the UpdateExpressions StateStore uses for TOKEN# and the live set."""

    def __init__(self):
        self.items = {}

    def put_item(self, Item):  # noqa: N803
        # The boto3 Table resource reads numbers back as Decimal; mimic it so handlers must convert.
        self.items[Item["pk"]] = {k: Decimal(v) if isinstance(v, int) and not isinstance(v, bool) else v
                                  for k, v in Item.items()}

    def get_item(self, Key, ConsistentRead=False):  # noqa: N803
        item = self.items.get(Key["pk"])
        return {"Item": dict(item)} if item else {}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues,  # noqa: N803
                    ConditionExpression=None):  # noqa: N803
        pk, values = Key["pk"], ExpressionAttributeValues
        if ConditionExpression == "attribute_exists(pk)" and pk not in self.items:
            raise _ccf()
        item = self.items.setdefault(pk, {"pk": pk})
        if UpdateExpression == "ADD incident_ids :i":
            item["incident_ids"] = set(item.get("incident_ids") or set()) | values[":i"]
        elif UpdateExpression == "DELETE incident_ids :i":
            remaining = set(item.get("incident_ids") or set()) - values[":i"]
            if remaining:
                item["incident_ids"] = remaining
            else:
                item.pop("incident_ids", None)
        elif UpdateExpression.startswith("SET started_at = if_not_exists"):
            item.setdefault("started_at", values[":now"])
            item["last_progress"] = values[":d"]
        elif UpdateExpression == "SET consumed_at = :now, outcome = :o":
            item["consumed_at"], item["outcome"] = values[":now"], values[":o"]
        else:
            raise AssertionError(f"unexpected UpdateExpression {UpdateExpression}")
