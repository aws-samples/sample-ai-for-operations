# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""`callback`: aws.aidevops events -> SendTask* (tasks.md 3.3; design.md D§3.3, D§3.3a, D§3.4, D§6.3).

Step Functions, STS and the `devops-agent` journal are botocore Stubbers on the pinned models, so
every request's parameter names (`limit`, `order`, `recordType`, ...) are checked against the
model. S3 and DynamoDB are in-memory fakes. No network.
"""

import datetime as dt
import json
import time
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from drift_core.collectors import CLIENT_CONFIG
from drift_core.logging_util import clear_secrets
from drift_core.state_store import LIVE_PK, StateStore
from drift_core.webhook import investigation_tag
from handlers import aws_clients, callback, investigate
from tests.unit.handlers.fakes import (
    ACCOUNT,
    BUCKET,
    DEVOPS_ACCOUNT,
    REGION,
    RUN_ID,
    SECRET,
    SECRET_PARAM,
    SPACE,
    TABLE,
    WEBHOOK_URL,
    Clients,
    Context,
    FakeS3,
    FakeTable,
    captured_logs,
    fenced,
    fid,
    finding,
    incident,
    log_lines,
    result_doc,
    seed_run,
    stubbed,
)

TOKENS = {1: "AQB-callback-token-1-" + "c" * 60, 2: "AQB-callback-token-2-" + "d" * 60}
BATCH = {1: [fid(1), fid(2), fid(3)], 2: [fid(4), fid(5)]}
ROLE_ARN = f"arn:aws:iam::{DEVOPS_ACCOUNT}:role/nrdc-journal-reader-{ACCOUNT}-{REGION}"
ASSUMED = {"AccessKeyId": "ASIAASSUMEDKEY000001", "SecretAccessKey": "assumed-secret-key-0123456789",  # noqa: E501  # gitleaks:allow -- synthetic Stubber fixture, never sent to AWS
           "SessionToken": "assumed-session-token-0123456789",
           "Expiration": dt.datetime(2026, 10, 13, 6, tzinfo=dt.UTC)}
URL = f"https://{SPACE}.aidevops.global.app.aws/investigation/t1"  # same Agent Space as the events
CREATED = dt.datetime(2026, 10, 13, 5, 1, tzinfo=dt.UTC)


def iid(n):
    return f"nrdc-{RUN_ID}-{n}"


@pytest.fixture
def world(monkeypatch):
    clear_secrets()
    s3, table = FakeS3(), FakeTable()
    sfn, sfn_stub = stubbed("stepfunctions")
    agent, agent_stub = stubbed("devops-agent")
    sts, sts_stub = stubbed("sts")
    ssm, ssm_stub = stubbed("ssm")
    clients = Clients(s3=s3, stepfunctions=sfn, sts=sts, ssm=ssm, **{"devops-agent": agent})
    monkeypatch.setattr(aws_clients, "client", clients)
    monkeypatch.setattr(aws_clients, "table", lambda name: table)
    monkeypatch.delenv("DEVOPS_AGENT_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("PRODUCTION_TAG_VALUES", raising=False)
    for key, value in {"BUCKET_NAME": BUCKET, "TABLE_NAME": TABLE, "DEVOPS_AGENT_SPACE_ID": SPACE,
                       "DEVOPS_AGENT_WEBHOOK_URL": WEBHOOK_URL, "WEBHOOK_SECRET_PARAMETER_NAME": SECRET_PARAM,
                       "MAX_FINDINGS_PER_INVESTIGATION": "3"}.items():
        monkeypatch.setenv(key, value)
    w = SimpleNamespace(s3=s3, table=table, sfn=sfn_stub, agent=agent_stub, sts=sts_stub, ssm=ssm_stub,
                        clients=clients, store=StateStore(table))
    yield w
    for stub in (sfn_stub, agent_stub, sts_stub, ssm_stub):
        stub.assert_no_pending_responses()
    clear_secrets()


def put_token(w, n, ttl_offset=3600):
    w.store.put_token(iid(n), task_token=TOKENS[n], run_id=RUN_ID, batch_n=n, finding_ids=BATCH[n],
                      finding_kinds={f: "blackhole-route" for f in BATCH[n]}, created_at="2026-10-13T05:01:00Z",
                      ttl=int(time.time()) + ttl_offset)


def event(detail_type, execution="exec-1", space=SPACE, summary=None, task="t1"):
    meta = {"agent_space_id": space, "task_id": task}
    if execution:
        meta["execution_id"] = execution
    data = {"status": "x", "priority": "HIGH", "created_at": "2026-10-13T05:01:00Z"}
    if summary:
        data["summary_record_id"] = summary
    return {"version": "0", "source": "aws.aidevops", "detail-type": detail_type,
            "detail": {"metadata": meta, "data": data}}


def record(rid, rtype, content, execution="exec-1"):
    return {"agentSpaceId": SPACE, "executionId": execution, "recordId": rid, "content": content,
            "createdAt": CREATED, "recordType": rtype}


def message(role, text):
    return {"role": role, "content": [{"type": "text", "text": text}, {"type": "toolUse", "name": "x"}]}


def journal_params(execution, record_type, order, limit, next_token=None):
    params = {"agentSpaceId": SPACE, "executionId": execution, "recordType": record_type, "order": order,
              "limit": limit}
    if next_token:
        params["nextToken"] = next_token
    return params


def expect_first(stub, n=1, execution="exec-1", text=None, content=None):
    text = text if text is not None else f"{investigation_tag(RUN_ID, n)}\nNETWORK ROUTING DRIFT — NEW FINDINGS"
    content = content if content is not None else message("user", text)
    stub.add_response("list_journal_records", {"records": [record("r-first", "message", content, execution)]},
                      journal_params(execution, "message", "ASC", 1))


def expect_summary(stub, pages, execution="exec-1"):
    for i, records in enumerate(pages):
        response = {"records": records}
        if i < len(pages) - 1:
            response["nextToken"] = f"page-{i + 1}"
        stub.add_response("list_journal_records", response,
                          journal_params(execution, "investigation_summary_md", "ASC", 100,
                                         f"page-{i}" if i else None))


def expect_last_assistant(stub, text, execution="exec-1"):
    records = [record("r-tool", "message", message("user", "tool result"), execution),
               record("r-last", "message", message("assistant", text), execution)]
    stub.add_response("list_journal_records", {"records": records},
                      journal_params(execution, "message", "DESC", 20))


def expect_success(w, n, count, url=URL):
    output = {"batch_n": n, "status": "ok", "incident_id": iid(n),
              "artifact": f"runs/{RUN_ID}/investigation-{n}.json", "incident_count": count, "investigation_url": url}
    w.sfn.add_response("send_task_success", {}, {"taskToken": TOKENS[n], "output": json.dumps(output)})


def expect_failure(w, n, error, cause=ANY):
    w.sfn.add_response("send_task_failure", {}, {"taskToken": TOKENS[n], "error": error, "cause": cause})


def token_item(w, n):
    return w.table.items[f"TOKEN#{iid(n)}"]


def live(w):
    return set(w.table.items.get(LIVE_PK, {}).get("incident_ids") or set())


def batch1_doc(**kwargs):
    return result_doc(1, [incident([fid(1), fid(2)], rank=1, env="dev", title="dev first"),
                          incident([fid(3)], rank=2, env="prod", title="prod second")], **kwargs)


# --- Ignored and dropped events -----------------------------------------------------------------

@pytest.mark.parametrize("evt", [
    event("Investigation Pending Triage"), event("Something Else"), {"detail-type": None}, "not-an-event",
    event("Investigation Completed", execution=None), event("Investigation In Progress", space=""),
    event("Investigation Completed", space="as-other-space")])
def test_events_without_execution_or_other_space_are_ignored_without_any_call(world, evt):
    assert callback.handler(evt, Context()) == {"status": "ignored"}
    assert world.clients.calls == []


@pytest.mark.parametrize("arrange", [
    lambda w: expect_first(w.agent, text="Some other investigation, no tag"),
    lambda w: expect_first(w.agent, text="[INVESTIGATION_ID:other-123] not ours"),
    lambda w: expect_first(w.agent, content=message("assistant", f"{investigation_tag(RUN_ID, 1)}")),
    lambda w: expect_first(w.agent, content="plain text record, not JSON"),
    lambda w: w.agent.add_response("list_journal_records", {"records": []},
                                   journal_params("exec-1", "message", "ASC", 1)),
])
def test_untagged_first_message_is_dropped(world, arrange):
    put_token(world, 1)
    arrange(world)
    assert callback.handler(event("Investigation Completed", summary="s-1"), Context()) == {"status": "dropped"}
    assert "consumed_at" not in token_item(world, 1)


@pytest.mark.parametrize("arrange", [
    lambda w: None,                                                      # no TOKEN# item at all
    lambda w: put_token(w, 1, ttl_offset=-5),                            # TTL passed
    lambda w: (put_token(w, 1), w.store.consume_token(iid(1), "2026-10-13T05:05:00Z", "ok")),  # already used
])
def test_tagged_event_without_live_token_is_dropped(world, arrange):
    arrange(world)
    expect_first(world.agent)
    assert callback.handler(event("Investigation Completed"), Context()) == {"status": "dropped"}


def test_first_message_as_json_string_content_correlates(world):
    put_token(world, 1)
    expect_first(world.agent, content=json.dumps({"role": "user", "content": investigation_tag(RUN_ID, 1)}))
    world.sfn.add_response("send_task_heartbeat", {}, {"taskToken": TOKENS[1]})
    assert callback.handler(event("Investigation Created"), Context()) == {"status": "heartbeat"}


# --- Completed ----------------------------------------------------------------------------------

def test_completed_reads_summary_record_validates_resorts_writes_artifact_and_succeeds(world):
    put_token(world, 1)
    put_token(world, 2)
    expect_first(world.agent)
    summary = record("s-1", "investigation_summary_md", {"markdown": fenced(batch1_doc(url=URL))})
    expect_summary(world.agent, [[record("s-0", "investigation_summary_md", "other")], [summary]])
    expect_success(world, 1, count=2)
    with captured_logs() as buffer:
        assert callback.handler(event("Investigation Completed", summary="s-1"), Context()) == {"status": "ok"}
    artifact = world.s3.json(f"runs/{RUN_ID}/investigation-1.json")
    assert artifact["run_id"] == RUN_ID and artifact["batch_n"] == 1 and artifact["execution_id"] == "exec-1"
    # Code order, not the agent's: prod (score 1010) above dev (score 101) despite agent rank 2.
    assert [(i["title"], i["rank"], i["agent_rank"]) for i in artifact["incidents"]] == [
        ("prod second", 1, 2), ("dev first", 2, 1)]
    assert [i["blast_radius"]["score"] for i in artifact["incidents"]] == [1010, 101]
    assert token_item(world, 1)["outcome"] == "ok" and live(world) == {iid(2)}
    assert TOKENS[1] not in buffer.getvalue()
    assert any(line["message"] == "batch_succeeded" for line in log_lines(buffer))


def test_completed_without_summary_id_uses_last_assistant_message_and_default_url(world):
    put_token(world, 1)
    expect_first(world.agent)
    expect_last_assistant(world.agent, fenced(batch1_doc(), info="json"))
    expect_success(world, 1, count=2, url=f"https://{SPACE}.aidevops.global.app.aws/investigation/t9")
    assert callback.handler(event("Investigation Completed", task="t9"), Context()) == {"status": "ok"}


def test_block_in_an_earlier_assistant_message_is_found(world):
    """Live 2026-10-15: the agent posted follow-up messages after its conclusion."""
    put_token(world, 1)
    expect_first(world.agent)
    records = [record("r-later", "message", message("assistant", "Mitigation handed off; investigation concluded.")),
               record("r-tool", "message", message("user", "tool result")),
               record("r-final", "message", message("assistant", fenced(batch1_doc(url=URL))))]
    world.agent.add_response("list_journal_records", {"records": records},
                             journal_params("exec-1", "message", "DESC", 20))
    expect_success(world, 1, count=2)
    assert callback.handler(event("Investigation Completed"), Context()) == {"status": "ok"}


@pytest.mark.parametrize("summary_content", [
    {"markdown": "# Summary\nNo structured block here."},       # summary has no block
    {"markdown": fenced("{not json")},                          # summary block unparseable
    None,                                                       # summary record not found
])
def test_summary_without_parseable_block_falls_back_to_last_assistant(world, summary_content):
    put_token(world, 1)
    expect_first(world.agent)
    records = [record("s-1", "investigation_summary_md", summary_content)] if summary_content else []
    expect_summary(world.agent, [records])
    expect_last_assistant(world.agent, fenced(batch1_doc(url=URL)))
    expect_success(world, 1, count=2)
    assert callback.handler(event("Investigation Completed", summary="s-1"), Context()) == {"status": "ok"}


@pytest.mark.parametrize("assistant_text, cause", [
    ("I looked around and found nothing.", "without an nrdc-investigation/v1 block"),
    (fenced('{"schema": "nrdc-investigation/v1", '), "not valid JSON"),
])
def test_completed_without_parseable_block_is_no_result(world, assistant_text, cause):
    put_token(world, 1)
    expect_first(world.agent)
    expect_last_assistant(world.agent, assistant_text)
    expect_failure(world, 1, "NO_RESULT")
    with captured_logs("callback") as buffer:
        assert callback.handler(event("Investigation Completed"), Context()) == {"status": "NO_RESULT"}
    assert token_item(world, 1)["outcome"] == "failed:NO_RESULT" and not live(world)
    (line,) = [entry for entry in log_lines(buffer) if entry["message"] == "batch_failed"]
    assert cause in line["cause"]


def test_completed_with_no_assistant_message_is_no_result(world):
    put_token(world, 1)
    expect_first(world.agent)
    world.agent.add_response("list_journal_records",
                             {"records": [record("r-u", "message", message("user", "only the request"))]},
                             journal_params("exec-1", "message", "DESC", 20))
    expect_failure(world, 1, "NO_RESULT", cause="investigation completed without an nrdc-investigation/v1 block")
    assert callback.handler(event("Investigation Completed"), Context()) == {"status": "NO_RESULT"}


@pytest.mark.parametrize("doc, needle", [
    (result_doc(1, [incident([fid(1), fid(2), fid(3), fid(4)])]), "not in this batch"),  # batch 2's ID
    (result_doc(1, [incident([fid(1)])]), "missing"),
    (result_doc(2, [incident(BATCH[1])]), "is not this batch"),
    (result_doc(1, [incident(BATCH[1], rank=2)]), "permutation"),
    ({"schema": "nrdc-investigation/v0"}, "required"),
])
def test_batch_scoped_validation_failure_is_schema_invalid(world, doc, needle):
    put_token(world, 1)
    expect_first(world.agent)
    expect_last_assistant(world.agent, fenced(doc))
    expect_failure(world, 1, "SCHEMA_INVALID")
    with captured_logs("callback") as buffer:
        assert callback.handler(event("Investigation Completed"), Context()) == {"status": "SCHEMA_INVALID"}
    (line,) = [entry for entry in log_lines(buffer) if entry["message"] == "batch_failed"]
    assert needle in line["cause"] and line["error"] == "SCHEMA_INVALID"
    assert f"runs/{RUN_ID}/investigation-1.json" not in {k for _, k in world.s3.objects}


def test_success_for_a_token_step_functions_no_longer_knows_is_not_an_error(world):
    put_token(world, 1)
    expect_first(world.agent)
    expect_last_assistant(world.agent, fenced(batch1_doc(url=URL)))
    world.sfn.add_client_error("send_task_success", service_error_code="TaskTimedOut", http_status_code=400)
    assert callback.handler(event("Investigation Completed"), Context()) == {"status": "ok"}
    assert token_item(world, 1)["outcome"] == "expired"


def test_s3_write_failure_raises_and_keeps_token_live_for_the_retry(world, monkeypatch):
    put_token(world, 1)
    expect_first(world.agent)
    expect_last_assistant(world.agent, fenced(batch1_doc(url=URL)))

    def denied(**_):
        raise ClientError({"Error": {"Code": "AccessDenied"}}, "PutObject")

    monkeypatch.setattr(world.s3, "put_object", denied)
    with pytest.raises(Exception, match="could not write"):
        callback.handler(event("Investigation Completed"), Context())
    assert "consumed_at" not in token_item(world, 1) and live(world) == {iid(1)}


# --- Two batches: each callback carries only its own batch's IDs (regression, tasks.md 3.3) -----

def test_two_batches_each_with_only_its_own_ids_validate_end_to_end(world, monkeypatch):
    seed_run(world.s3, [finding(i, env="prod" if i in (2, 4) else "dev") for i in range(1, 6)])
    plan = investigate.batch_handler({"run_id": RUN_ID}, Context())
    assert plan["batch_count"] == 2
    posts = []
    monkeypatch.setattr(investigate, "post", lambda url, body, headers, timeout: posts.append(body) or 202)
    for n in (1, 2):
        world.ssm.add_response("get_parameter", {"Parameter": {"Name": SECRET_PARAM, "Value": SECRET}},
                               {"Name": SECRET_PARAM, "WithDecryption": True})
        investigate.handler({"run_id": RUN_ID, "batch": plan["batches"][n - 1], "task_token": TOKENS[n]}, Context())
    ids = {n: list(token_item(world, n)["finding_ids"]) for n in (1, 2)}
    assert sorted(ids[1] + ids[2]) == [fid(i) for i in range(1, 6)]

    docs = {n: result_doc(n, [incident([f], rank=r, env="prod" if f in (fid(2), fid(4)) else "dev", title=f)
                              for r, f in enumerate(ids[n], start=1)], url=URL) for n in (1, 2)}
    outputs = {}
    for n in (2, 1):  # out of order on purpose
        execution = f"exec-{n}"
        expect_first(world.agent, execution=execution, text=json.loads(posts[n - 1])["description"])
        expect_last_assistant(world.agent, fenced(docs[n]), execution=execution)
        expect_success(world, n, count=len(ids[n]))
        outputs[n] = {"batch_n": n, "status": "ok"}
        assert callback.handler(event("Investigation Completed", execution=execution), Context()) == {"status": "ok"}
    assert not live(world)

    merged = investigate.merge_handler({"run_id": RUN_ID, "results": [
        {"batch_n": n, "result": outputs[n]} for n in (1, 2)]}, Context())
    assert merged["ok_batches"] == 2 and merged["invariant_ok"] is True
    incidents = world.s3.json(f"runs/{RUN_ID}/investigation.json")["incidents"]
    # One ordered list across batches: both prod incidents above every dev incident at equal counts.
    assert [i["blast_radius"]["environment"] for i in incidents] == ["prod", "prod", "dev", "dev", "dev"]
    assert {i["batch_n"] for i in incidents[:2]} == {1, 2}


# --- Failures and progress ----------------------------------------------------------------------

@pytest.mark.parametrize("detail_type", callback.FAILURES)
def test_terminal_failure_events_fail_the_batch_with_the_detail_type(world, detail_type):
    put_token(world, 1)
    expect_first(world.agent)
    expect_failure(world, 1, detail_type, cause=f"{detail_type} (task t1)")
    assert callback.handler(event(detail_type), Context()) == {"status": "failed"}
    assert token_item(world, 1)["outcome"] == f"failed:{detail_type}" and not live(world)


def test_send_task_failure_service_error_raises(world):
    put_token(world, 1)
    expect_first(world.agent)
    world.sfn.add_client_error("send_task_failure", service_error_code="InternalError", http_status_code=500)
    with pytest.raises(ClientError):
        callback.handler(event("Investigation Failed"), Context())
    assert live(world) == {iid(1)}


@pytest.mark.parametrize("detail_type", callback.PROGRESS)
def test_progress_events_heartbeat_and_record_started_at_once(world, detail_type):
    put_token(world, 1)
    for _ in range(2):
        expect_first(world.agent)
        world.sfn.add_response("send_task_heartbeat", {}, {"taskToken": TOKENS[1]})
    assert callback.handler(event(detail_type), Context()) == {"status": "heartbeat"}
    first = token_item(world, 1)["started_at"]
    assert token_item(world, 1)["last_progress"] == detail_type
    callback.handler(event(detail_type), Context())
    assert token_item(world, 1)["started_at"] == first and "consumed_at" not in token_item(world, 1)
    assert live(world) == {iid(1)}


def test_heartbeat_for_a_gone_token_releases_it(world):
    put_token(world, 1)
    expect_first(world.agent)
    world.sfn.add_client_error("send_task_heartbeat", service_error_code="TaskTimedOut", http_status_code=400)
    with captured_logs("callback") as buffer:
        assert callback.handler(event("Investigation In Progress"), Context()) == {"status": "heartbeat"}
    assert token_item(world, 1)["outcome"] == "expired" and "started_at" not in token_item(world, 1)
    assert any(line["message"] == "task_token_gone" for line in log_lines(buffer))


# --- Journal access denied (same account) -------------------------------------------------------

def test_journal_denied_before_correlation_fails_every_outstanding_token(world):
    put_token(world, 1)
    put_token(world, 2)
    world.store.put_token(f"nrdc-{RUN_ID}-9", task_token="old-token-xxxxxxxx", run_id=RUN_ID, batch_n=9,  # nosec B106 -- fixture task token, not a credential
                          finding_ids=[], finding_kinds={}, created_at="x", ttl=int(time.time()) - 1)
    world.agent.add_client_error("list_journal_records", service_error_code="AccessDeniedException",
                                 http_status_code=403)
    expect_failure(world, 1, "JOURNAL_ACCESS_DENIED")
    expect_failure(world, 2, "JOURNAL_ACCESS_DENIED")
    with captured_logs("callback") as buffer:
        assert callback.handler(event("Investigation Completed"), Context()) == {"status": "JOURNAL_ACCESS_DENIED"}
    assert not live(world)
    assert world.table.items[f"TOKEN#nrdc-{RUN_ID}-9"]["outcome"] == "expired"
    (line,) = [entry for entry in log_lines(buffer) if entry["message"] == "journal_access_denied"]
    assert line["level"] == "ERROR" and line["batches_failed"] == 2 and line["cross_account"] is False


def test_journal_denied_with_nothing_outstanding_is_logged_and_raised(world):
    world.agent.add_client_error("list_journal_records", service_error_code="AccessDeniedException",
                                 http_status_code=403)
    with captured_logs("callback") as buffer, pytest.raises(callback.JournalAccessDenied):
        callback.handler(event("Investigation In Progress"), Context())
    assert any(line["message"] == "journal_access_denied" for line in log_lines(buffer))


def test_journal_denied_after_correlation_fails_that_batch_only(world):
    put_token(world, 1)
    put_token(world, 2)
    expect_first(world.agent)
    world.agent.add_client_error("list_journal_records", service_error_code="AccessDeniedException",
                                 http_status_code=403)
    expect_failure(world, 1, "JOURNAL_ACCESS_DENIED")
    assert callback.handler(event("Investigation Completed", summary="s-1"), Context()) == {
        "status": "JOURNAL_ACCESS_DENIED"}
    assert live(world) == {iid(2)}


def test_other_journal_errors_raise_for_async_retry(world):
    put_token(world, 1)
    world.agent.add_client_error("list_journal_records", service_error_code="ThrottlingException",
                                 http_status_code=429)
    with pytest.raises(ClientError):
        callback.handler(event("Investigation Completed"), Context())
    assert live(world) == {iid(1)}


def test_same_account_id_configured_does_not_assume_a_role(world, monkeypatch):
    monkeypatch.setenv("DEVOPS_AGENT_ACCOUNT_ID", ACCOUNT)
    put_token(world, 1)
    expect_first(world.agent)
    world.sfn.add_response("send_task_heartbeat", {}, {"taskToken": TOKENS[1]})
    callback.handler(event("Investigation Created"), Context())
    assert "sts" not in world.clients.services() and ("devops-agent", REGION) in world.clients.calls


# --- Cross-account (D§3.3a) ---------------------------------------------------------------------

@pytest.fixture
def cross(world, monkeypatch):
    """DEVOPS_AGENT_ACCOUNT_ID != own account. The journal client is built by the REAL
    `assumed_client`; a Stubber is attached to that very client, so a journal read can only succeed
    on the client that carries the assumed credentials."""
    monkeypatch.setenv("DEVOPS_AGENT_ACCOUNT_ID", DEVOPS_ACCOUNT)
    real = aws_clients.assumed_client
    state = SimpleNamespace(built=[], prepare=lambda stub: None, stub=None)

    def assumed(service, region, credentials):
        client = real(service, region, credentials)
        creds = client._get_credentials()
        state.built.append((service, region, creds.access_key, creds.secret_key, creds.token,
                            client.meta.service_model.signing_name))
        state.stub = Stubber(client)
        state.prepare(state.stub)
        state.stub.activate()
        return client

    monkeypatch.setattr(aws_clients, "assumed_client", assumed)
    yield state
    if state.stub:
        state.stub.assert_no_pending_responses()


def expect_assume(world):
    world.sts.add_response("assume_role", {"Credentials": ASSUMED},
                           {"RoleArn": ROLE_ARN, "RoleSessionName": "nrdc-callback", "DurationSeconds": 900})


def test_cross_account_assumes_journal_reader_and_reads_with_assumed_credentials(world, cross):
    put_token(world, 1)
    expect_assume(world)  # exactly one AssumeRole for both journal reads below

    def prepare(stub):
        expect_first(stub)
        expect_summary(stub, [[record("s-1", "investigation_summary_md", json.dumps(fenced(batch1_doc(url=URL))))]])

    cross.prepare = prepare
    expect_success(world, 1, count=2)
    with captured_logs() as buffer:
        assert callback.handler(event("Investigation Completed", summary="s-1"), Context()) == {"status": "ok"}
    assert cross.built == [("devops-agent", REGION, ASSUMED["AccessKeyId"], ASSUMED["SecretAccessKey"],
                            ASSUMED["SessionToken"], "aidevops")]
    assert "devops-agent" not in world.clients.services()  # never the function's own credentials
    assert ("sts", REGION) in world.clients.calls
    logs = buffer.getvalue()
    assert ASSUMED["SecretAccessKey"] not in logs and ASSUMED["SessionToken"] not in logs


def test_cross_account_progress_event(world, cross):
    put_token(world, 1)
    expect_assume(world)
    cross.prepare = lambda stub: expect_first(stub)
    world.sfn.add_response("send_task_heartbeat", {}, {"taskToken": TOKENS[1]})
    assert callback.handler(event("Investigation In Progress"), Context()) == {"status": "heartbeat"}
    assert len(cross.built) == 1


@pytest.mark.parametrize("code", ["AccessDenied", "ExpiredToken"])
def test_cross_account_assume_role_denied_fails_outstanding_tokens(world, cross, code):
    put_token(world, 1)
    world.sts.add_client_error("assume_role", service_error_code=code, http_status_code=403,
                               expected_params={"RoleArn": ROLE_ARN, "RoleSessionName": "nrdc-callback",
                                                "DurationSeconds": 900})
    expect_failure(world, 1, "JOURNAL_ACCESS_DENIED")
    with captured_logs("callback") as buffer:
        assert callback.handler(event("Investigation Completed"), Context()) == {"status": "JOURNAL_ACCESS_DENIED"}
    assert token_item(world, 1)["outcome"] == "failed:JOURNAL_ACCESS_DENIED" and not live(world)
    (line,) = [entry for entry in log_lines(buffer) if entry["message"] == "journal_access_denied"]
    assert line["cross_account"] is True and ROLE_ARN in line["reason"] and cross.built == []


def test_cross_account_assume_role_denied_without_token_is_logged_and_raised(world, cross):
    world.sts.add_client_error("assume_role", service_error_code="AccessDenied", http_status_code=403)
    with captured_logs("callback") as buffer, pytest.raises(callback.JournalAccessDenied, match="nrdc-journal-reader"):
        callback.handler(event("Investigation Completed"), Context())
    (line,) = [entry for entry in log_lines(buffer) if entry["message"] == "journal_access_denied"]
    assert line["level"] == "ERROR" and line["batches_failed"] == 0


def test_cross_account_other_sts_error_raises(world, cross):
    put_token(world, 1)
    world.sts.add_client_error("assume_role", service_error_code="RegionDisabledException", http_status_code=403)
    with pytest.raises(ClientError):
        callback.handler(event("Investigation Completed"), Context())
    assert live(world) == {iid(1)}


def test_cross_account_denied_journal_read_with_assumed_role(world, cross):
    put_token(world, 1)
    expect_assume(world)
    cross.prepare = lambda stub: stub.add_client_error("list_journal_records",
                                                       service_error_code="AccessDeniedException",
                                                       http_status_code=403)
    expect_failure(world, 1, "JOURNAL_ACCESS_DENIED")
    assert callback.handler(event("Investigation Completed"), Context()) == {"status": "JOURNAL_ACCESS_DENIED"}


# --- Text helpers and client factories ----------------------------------------------------------

def test_text_helpers_cover_document_shapes():
    assert callback._message_text({"content": "plain"}) == "plain"
    assert callback._message_text({"content": 7}) == ""
    assert callback._all_text({"a": ["x", {"b": "y"}, 3]}) == "x\ny\n"
    assert callback._all_text('"quoted"') == "quoted"


def test_aws_client_factories(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    sfn = aws_clients.client("stepfunctions", "eu-west-1")
    assert sfn.meta.region_name == "eu-west-1" and sfn.meta.config.retries == CLIENT_CONFIG.retries
    assumed = aws_clients.assumed_client("devops-agent", REGION, ASSUMED)
    creds = assumed._get_credentials()
    assert (creds.access_key, creds.secret_key, creds.token) == (
        ASSUMED["AccessKeyId"], ASSUMED["SecretAccessKey"], ASSUMED["SessionToken"])
    table = aws_clients.table(TABLE)
    assert table.name == TABLE and table.meta.client.meta.region_name == REGION
