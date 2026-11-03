# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""BatchFindings, `investigate` and MergeInvestigations (tasks.md 3.2; design.md D§3.2, D§3.3, D§6.1).

No network: SSM is a botocore Stubber on the pinned model, the webhook POST is replaced, S3 and
DynamoDB are in-memory fakes.
"""

import json
import os
import re
import time
from types import SimpleNamespace

import pytest
from botocore.exceptions import EndpointConnectionError

from drift_core import investigation as inv
from drift_core.logging_util import clear_secrets, get_logger, log_event
from drift_core.run_info import InputError
from drift_core.state_store import LIVE_PK, StateStore
from drift_core.webhook import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    WebhookClientError,
    WebhookConfigError,
    WebhookError,
    WebhookServerError,
    WebhookTimeout,
    WebhookTransportError,
    investigation_tag,
    sign,
)
from handlers import aws_clients, investigate
from tests.unit.handlers.fakes import (
    BUCKET,
    RUN_ID,
    SECRET,
    SECRET_PARAM,
    TABLE,
    WEBHOOK_URL,
    Clients,
    Context,
    FakeS3,
    FakeTable,
    captured_logs,
    fid,
    finding,
    incident,
    log_lines,
    result_doc,
    seed_run,
    stubbed,
)

TOKEN1, TOKEN2 = "AQB-task-token-one-" + "a" * 60, "AQB-task-token-two-" + "b" * 60
ENV_KEYS = ("DEVOPS_AGENT_ACCOUNT_ID", "DEVOPS_AGENT_SPACE_ID", "INVESTIGATION_TIMEOUT_SECONDS",
            "WEBHOOK_TIMEOUT_SECONDS", "INVESTIGATION_DESCRIPTION_MAX_BYTES", "LOG_LEVEL")


@pytest.fixture
def world(monkeypatch):
    clear_secrets()
    s3, table = FakeS3(), FakeTable()
    ssm, ssm_stub = stubbed("ssm")
    clients = Clients(s3=s3, ssm=ssm)
    monkeypatch.setattr(aws_clients, "client", clients)
    monkeypatch.setattr(aws_clients, "table", lambda name: table)
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in {"BUCKET_NAME": BUCKET, "TABLE_NAME": TABLE, "ENABLE_DEVOPS_AGENT_HANDOFF": "true",
                       "DEVOPS_AGENT_WEBHOOK_URL": WEBHOOK_URL, "WEBHOOK_SECRET_PARAMETER_NAME": SECRET_PARAM,
                       "MAX_FINDINGS_PER_INVESTIGATION": "3"}.items():
        monkeypatch.setenv(key, value)
    posts = []

    def fake_post(url, body, headers, timeout):
        # The token must already be stored when the agent could first call back.
        stored = any(k.startswith("TOKEN#") for k in table.items)
        posts.append(SimpleNamespace(url=url, body=body, headers=headers, timeout=timeout, token_stored=stored))
        if world_ns.post_error:
            raise world_ns.post_error
        return 200

    monkeypatch.setattr(investigate, "post", fake_post)
    world_ns = SimpleNamespace(s3=s3, table=table, ssm_stub=ssm_stub, clients=clients, posts=posts, post_error=None)
    yield world_ns
    ssm_stub.assert_no_pending_responses()
    clear_secrets()


def expect_secret(world, value=SECRET):
    world.ssm_stub.add_response(
        "get_parameter", {"Parameter": {"Name": SECRET_PARAM, "Type": "SecureString", "Value": value, "Version": 1}},
        {"Name": SECRET_PARAM, "WithDecryption": True})


def plan(world, n=5):
    seed_run(world.s3, [finding(i, env="prod" if i % 2 else "dev") for i in range(1, n + 1)])
    return investigate.batch_handler({"run_id": RUN_ID}, Context())


def invoke(n=1, token=TOKEN1):
    return investigate.handler({"run_id": RUN_ID, "batch": {"run_id": RUN_ID, "batch_n": n, "batches": 2},
                                "task_token": token}, Context())


def incident_id(n):
    return f"nrdc-{RUN_ID}-{n}"


# --- BatchFindings ------------------------------------------------------------------------------

def test_batch_handler_splits_new_drift_findings_and_writes_plan(world):
    out = plan(world)
    assert out == {"run_id": RUN_ID, "batch_count": 2,
                   "batches": [{"run_id": RUN_ID, "batch_n": 1, "batches": 2},
                               {"run_id": RUN_ID, "batch_n": 2, "batches": 2}]}
    saved = world.s3.json(f"runs/{RUN_ID}/investigation-batches.json")
    assert saved["new_finding_ids"] == [fid(i) for i in range(1, 6)]  # the informational note is not investigated
    assert [len(b["finding_ids"]) for b in saved["batches"]] == [3, 2]
    assert saved["batches"][0]["incident_id"] == incident_id(1)
    assert investigation_tag(RUN_ID, 1) in saved["batches"][0]["description"]
    assert "111111111111" in saved["batches"][0]["description"]  # account from the function ARN


@pytest.mark.parametrize("event, context", [({}, Context()), ({"run_id": RUN_ID}, None)])
def test_batch_handler_input_errors(world, event, context):
    with pytest.raises(InputError):
        investigate.batch_handler(event, context)


# --- investigate --------------------------------------------------------------------------------

def test_investigate_reads_secret_signs_posts_and_stores_token(world):
    plan(world)
    saved = world.s3.json(f"runs/{RUN_ID}/investigation-batches.json")["batches"][0]
    expect_secret(world)
    before = int(time.time())
    out = invoke(1)
    assert out == {"run_id": RUN_ID, "batch_n": 1, "incident_id": incident_id(1), "status": "posted"}

    (post,) = world.posts
    assert post.url == WEBHOOK_URL and post.timeout == 10 and post.token_stored
    body = json.loads(post.body)
    assert body["incidentId"] == incident_id(1) and body["description"] == saved["description"]
    assert body["data"] == {"run_id": RUN_ID, "batch": 1, "batches": 2}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", post.headers[TIMESTAMP_HEADER])
    assert post.headers[SIGNATURE_HEADER] == sign(SECRET, post.headers[TIMESTAMP_HEADER], post.body)

    token = world.table.items[f"TOKEN#{incident_id(1)}"]
    assert token["task_token"] == TOKEN1 and token["run_id"] == RUN_ID and token["batch_n"] == 1
    assert token["finding_ids"] == saved["finding_ids"] and token["finding_kinds"] == saved["finding_kinds"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", token["created_at"])
    assert token["ttl"] > before + 900  # outlives the Step Functions wait
    assert "consumed_at" not in token
    assert world.table.items[LIVE_PK]["incident_ids"] == {incident_id(1)}
    assert ("ssm", "us-east-1") in world.clients.calls


def test_token_ttl_follows_configured_timeout(world, monkeypatch):
    monkeypatch.setenv("INVESTIGATION_TIMEOUT_SECONDS", "3600")
    plan(world)
    expect_secret(world)
    before = int(time.time())
    invoke(1)
    assert world.table.items[f"TOKEN#{incident_id(1)}"]["ttl"] >= before + 3600 + investigate.TOKEN_TTL_MARGIN_SECONDS


def test_region_mismatch_fails_closed_before_secret_token_or_post(world, monkeypatch):
    monkeypatch.setenv("DEVOPS_AGENT_WEBHOOK_URL", "https://event-ai.eu-west-1.api.aws/webhook/generic/abc")
    plan(world)
    with pytest.raises(WebhookConfigError, match="eu-west-1 differs from this function's Region us-east-1"):
        invoke(1)
    assert "ssm" not in world.clients.services()
    assert not world.posts and not any(k.startswith("TOKEN#") for k in world.table.items)


@pytest.mark.parametrize("url", ["", "http://event-ai.us-east-1.api.aws/webhook/generic/abc",
                                 "https://example.com/webhook/generic/abc"])
def test_invalid_webhook_url_fails_closed(world, monkeypatch, url):
    monkeypatch.setenv("DEVOPS_AGENT_WEBHOOK_URL", url)
    plan(world)
    with pytest.raises(WebhookConfigError) as err:
        invoke(1)
    assert not url or url not in str(err.value)
    assert not world.posts and "ssm" not in world.clients.services()


@pytest.mark.parametrize("error", [WebhookServerError("webhook returned HTTP 503"),
                                   WebhookClientError("webhook returned HTTP 401"),
                                   WebhookTimeout("no response"), WebhookTransportError("tls")])
def test_webhook_error_is_raised_catchable_and_token_released(world, error):
    plan(world)
    expect_secret(world)
    world.post_error = error
    with captured_logs() as buffer, pytest.raises(WebhookError) as err:
        invoke(1)
    assert err.value is error and type(err.value).__name__ == type(error).__name__  # Step Functions error name
    token = world.table.items[f"TOKEN#{incident_id(1)}"]
    assert token["outcome"] == f"failed:{type(error).__name__}" and token["consumed_at"]
    assert not world.table.items[LIVE_PK].get("incident_ids")
    (line,) = [entry for entry in log_lines(buffer) if entry["message"] == "webhook_failed"]
    assert line["level"] == "ERROR" and line["error"] == type(error).__name__ and line["batch_n"] == 1


def test_retry_after_webhook_failure_re_arms_the_token(world):
    plan(world)
    expect_secret(world)
    world.post_error = WebhookServerError("webhook returned HTTP 503")
    with pytest.raises(WebhookServerError):
        invoke(1)
    world.post_error = None
    expect_secret(world)
    invoke(1)
    token = world.table.items[f"TOKEN#{incident_id(1)}"]
    assert "consumed_at" not in token and world.table.items[LIVE_PK]["incident_ids"] == {incident_id(1)}


def _ssm_client_error(world):
    world.ssm_stub.add_client_error("get_parameter", service_error_code="ParameterNotFound",
                                    service_message=f"Parameter {SECRET_PARAM} not found", http_status_code=400)


def _ssm_no_value(world):
    world.ssm_stub.add_response("get_parameter", {"Parameter": {"Name": SECRET_PARAM}},
                                {"Name": SECRET_PARAM, "WithDecryption": True})


def _ssm_empty(world):
    expect_secret(world, value="")


class _Unreachable:
    def get_parameter(self, **_):
        raise EndpointConnectionError(endpoint_url="https://ssm.us-east-1.amazonaws.com")


def _ssm_unreachable(world):
    world.clients.clients["ssm"] = _Unreachable()


@pytest.mark.parametrize("arrange, message", [
    (_ssm_client_error, r"\(ParameterNotFound\)"), (_ssm_no_value, r"\(KeyError\)"),
    (_ssm_empty, "is empty"), (_ssm_unreachable, r"\(EndpointConnectionError\)")])
def test_secret_read_failures_fail_closed_without_detail(world, arrange, message):
    plan(world)
    arrange(world)
    with pytest.raises(WebhookConfigError, match=message) as err:
        invoke(1)
    assert SECRET_PARAM not in str(err.value)
    assert not world.posts and not any(k.startswith("TOKEN#") for k in world.table.items)


def test_missing_secret_parameter_name_fails_closed(world, monkeypatch):
    monkeypatch.setenv("WEBHOOK_SECRET_PARAMETER_NAME", "")
    plan(world)
    with pytest.raises(WebhookConfigError, match="not configured"):
        invoke(1)
    assert not world.posts


@pytest.mark.parametrize("event, context, message", [
    ({"run_id": RUN_ID, "batch": {"batch_n": 1}}, Context(), "task_token"),
    ({"run_id": RUN_ID, "batch": {"batch_n": 0}, "task_token": TOKEN1}, Context(), "positive integer"),
    ({"run_id": RUN_ID, "batch": {"batch_n": True}, "task_token": TOKEN1}, Context(), "positive integer"),
    ({"run_id": RUN_ID, "batch": {"batch_n": "1"}, "task_token": TOKEN1}, Context(), "positive integer"),
    ({"batch": {"batch_n": 1}, "task_token": TOKEN1}, Context(), "run_id"),
    ({"run_id": RUN_ID, "batch": {"batch_n": 1}, "task_token": TOKEN1}, None, "invoked_function_arn"),
    ({"run_id": RUN_ID, "batch": {"batch_n": 9}, "task_token": TOKEN1}, Context(), "batch 9 not found"),
    ("not-a-dict", Context(), "task_token"),
])
def test_investigate_input_errors(world, event, context, message):
    plan(world)
    with pytest.raises(InputError, match=message):
        investigate.handler(event, context)
    assert not world.posts


def test_flat_event_batch_n_is_accepted(world):
    plan(world)
    expect_secret(world)
    out = investigate.handler({"run_id": RUN_ID, "batch_n": 2, "task_token": TOKEN2}, Context())
    assert out["incident_id"] == incident_id(2)


# --- Secret and URL redaction (tasks.md 3.2 acceptance, requirements §14.4) ----------------------

def test_secret_and_url_never_in_logs_returns_errors_artifacts_or_env(world):
    plan(world)
    returned, errors = [], []
    with captured_logs() as buffer:
        expect_secret(world)
        returned.append(invoke(1))
        expect_secret(world)
        world.post_error = WebhookClientError("webhook returned HTTP 401")
        with pytest.raises(WebhookError) as err:
            invoke(2, TOKEN2)
        errors.append(str(err.value))
        # Both values are on the redaction list: anything that tried to log them is masked.
        log_event(get_logger("investigate"), "probe", url=WEBHOOK_URL, secret=SECRET,
                  text=f"POST {WEBHOOK_URL} with {SECRET}")
    logs = buffer.getvalue()
    assert logs and "investigation_requested" in logs and "webhook_failed" in logs
    probe = log_lines(buffer)[-1]
    assert probe["url"] == probe["secret"] == "[REDACTED]" and probe["text"] == "POST [REDACTED] with [REDACTED]"
    surfaces = [logs, json.dumps(returned), *errors,
                *(body.decode() for body in world.s3.objects.values()),
                json.dumps(list(world.table.items.values()), default=str)]
    for surface in surfaces:
        assert SECRET not in surface
        assert WEBHOOK_URL not in surface
    assert TOKEN1 not in logs and TOKEN2 not in logs
    assert SECRET not in "".join(os.environ.values())  # read from SSM at runtime, never via env


# --- MergeInvestigations ------------------------------------------------------------------------

def _ok_artifact(world, batch_n, members):
    kinds = {f: "blackhole-route" for f in members}
    doc = result_doc(batch_n, [incident(members, env="prod")])
    normalized = inv.normalize(doc, finding_kinds=kinds, production_values=("prod",),
                               default_url="https://space.aidevops.global.app.aws/investigation/t1")
    world.s3.put(f"runs/{RUN_ID}/investigation-{batch_n}.json", normalized)


def _tokens(world, started=None):
    store = StateStore(world.table)
    batches = world.s3.json(f"runs/{RUN_ID}/investigation-batches.json")["batches"]
    for batch in batches:
        store.put_token(batch["incident_id"], task_token=f"tok-{batch['batch_n']}-xxxxxxxx", run_id=RUN_ID,
                        batch_n=batch["batch_n"], finding_ids=batch["finding_ids"],
                        finding_kinds=batch["finding_kinds"], created_at="2026-10-13T05:01:00Z",
                        ttl=int(time.time()) + 3600)
    for n in started or ():
        store.mark_started(incident_id(n), "2026-10-13T05:02:00Z", "Investigation In Progress")
    return batches


def test_merge_keeps_ok_batch_and_reports_timeout_running(world, capsys):
    plan(world)
    batches = _tokens(world, started=[2])
    _ok_artifact(world, 1, batches[0]["finding_ids"])
    StateStore(world.table).consume_token(incident_id(1), "2026-10-13T05:05:00Z", "ok")
    results = [{"run_id": RUN_ID, "batch_n": 1, "batches": 2,
                "result": {"batch_n": 1, "status": "ok", "incident_id": incident_id(1)}},
               {"run_id": RUN_ID, "batch_n": 2, "batches": 2,
                "error": {"Error": "States.Timeout", "Cause": "timed out"}}, "garbage"]
    out = investigate.merge_handler({"run_id": RUN_ID, "results": results}, Context())
    assert out == {"run_id": RUN_ID, "ok_batches": 1, "failed_batches": 1, "invariant_ok": True,
                   "batches": [{"batch_n": 1, "status": "ok"}, {"batch_n": 2, "status": "failed:timeout-running"}]}
    merged = world.s3.json(f"runs/{RUN_ID}/investigation.json")
    assert [inc["member_finding_ids"] for inc in merged["incidents"]] == [sorted(batches[0]["finding_ids"])]
    assert '"InvestigationFailed": 1' in capsys.readouterr().out
    assert world.table.items[f"TOKEN#{incident_id(1)}"]["outcome"] == "ok"  # already consumed: untouched
    assert world.table.items[f"TOKEN#{incident_id(2)}"]["outcome"] == "merged:failed"
    assert not world.table.items[LIVE_PK].get("incident_ids")


@pytest.mark.parametrize("result_2, reason", [
    ({"batch_n": 2, "status": "failed", "reason": "States.HeartbeatTimeout"}, "timeout-never-started"),
    ({"batch_n": 2, "Error": "SCHEMA_INVALID", "Cause": "bad"}, "SCHEMA_INVALID"),
    ({"batch_n": 2, "error": {"Cause": "x"}}, "unknown"),
    (None, "no result"),
])
def test_merge_failure_reasons(world, result_2, reason):
    plan(world)
    batches = _tokens(world)
    _ok_artifact(world, 1, batches[0]["finding_ids"])
    results = [{"batch_n": 1, "status": "ok"}] + ([result_2] if result_2 else [])
    out = investigate.merge_handler({"run_id": RUN_ID, "results": results}, Context())
    assert out["batches"][1] == {"batch_n": 2, "status": f"failed:{reason}"}
    assert world.table.items[f"TOKEN#{incident_id(1)}"]["outcome"] == "merged:ok"


def test_merge_logs_invariant_violation(world):
    plan(world)
    batches = _tokens(world)
    saved = world.s3.json(f"runs/{RUN_ID}/investigation-batches.json")
    saved["new_finding_ids"].append(fid(77))  # a NEW finding no batch carried: a batching bug
    world.s3.put(f"runs/{RUN_ID}/investigation-batches.json", saved)
    _ok_artifact(world, 1, batches[0]["finding_ids"])
    with captured_logs("merge") as buffer:
        out = investigate.merge_handler({"run_id": RUN_ID, "results": [{"batch_n": 1, "status": "ok"}]})
    assert out["invariant_ok"] is False
    (line,) = [entry for entry in log_lines(buffer) if entry["message"] == "merge_invariant_violated"]
    assert line["invariant"]["missing"] == [fid(77)]


def test_merge_requires_run_id(world):
    with pytest.raises(InputError):
        investigate.merge_handler({"results": []})
