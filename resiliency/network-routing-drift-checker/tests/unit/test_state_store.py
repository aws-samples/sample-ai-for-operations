# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""StateStore: TOKEN# items and the live-investigation set (design.md D§3.3, D§3.4, D§5.1)."""

import pytest
from botocore.exceptions import ClientError

from drift_core.state_store import LIVE_PK, StateStore
from tests.unit.handlers.fakes import FakeTable

ID = "nrdc-2026-10-13T05:00:00Z-a1b2c3d4-1"


def store_with_token(ttl=2_000_000_000):
    table = FakeTable()
    store = StateStore(table)
    store.put_token(ID, task_token="token-xxxxxxxx", run_id="r", batch_n=1, finding_ids=["f-1"],  # nosec B106 -- fixture task token, not a credential
                    finding_kinds={"f-1": "blackhole-route"}, created_at="2026-10-13T05:00:00Z", ttl=ttl)
    return table, store


def test_put_get_and_live_set():
    table, store = store_with_token()
    item = store.get_token(ID)
    assert item["pk"] == f"TOKEN#{ID}" and item["finding_ids"] == ["f-1"] and "status" not in item
    assert store.live_token(ID, 1_000) == item
    assert store.live_incident_ids() == [ID]


def test_live_token_rejects_expired_consumed_and_missing():
    _, store = store_with_token(ttl=100)
    assert store.live_token(ID, 100) is None
    assert store.live_token("nrdc-other-1", 0) is None
    _, store = store_with_token()
    store.consume_token(ID, "2026-10-13T05:05:00Z", "ok")
    assert store.live_token(ID, 0) is None and store.live_incident_ids() == []
    assert store.get_token(ID)["outcome"] == "ok"


def test_mark_started_keeps_first_time_and_ignores_missing_token():
    _, store = store_with_token()
    store.mark_started(ID, "t1", "Investigation Created")
    store.mark_started(ID, "t2", "Investigation In Progress")
    item = store.get_token(ID)
    assert item["started_at"] == "t1" and item["last_progress"] == "Investigation In Progress"
    store.mark_started("nrdc-gone-1", "t3", "Investigation Created")  # TTL-deleted: no error, not re-created
    assert store.get_token("nrdc-gone-1") is None


def test_consume_missing_token_still_leaves_live_set():
    table, store = store_with_token()
    del table.items[f"TOKEN#{ID}"]  # deleted by TTL while still in the live set
    store.consume_token(ID, "now", "expired")
    assert store.get_token(ID) is None and store.live_incident_ids() == []


class _Broken(FakeTable):
    def update_item(self, **kwargs):
        if kwargs["Key"]["pk"] != LIVE_PK:
            raise ClientError({"Error": {"Code": "ProvisionedThroughputExceededException"}}, "UpdateItem")
        return super().update_item(**kwargs)


@pytest.mark.parametrize("call", [lambda s: s.mark_started(ID, "t", "d"), lambda s: s.consume_token(ID, "t", "o")])
def test_other_dynamodb_errors_propagate(call):
    store = StateStore(_Broken())
    with pytest.raises(ClientError):
        call(store)


def test_load_open_follows_pagination():
    class Paged:
        def __init__(self):
            self.calls = []

        def query(self, **kwargs):
            self.calls.append(kwargs)
            if "ExclusiveStartKey" not in kwargs:
                return {"Items": [{"pk": "F#1"}], "LastEvaluatedKey": {"pk": "F#1"}}
            return {"Items": [{"pk": "F#2"}]}

    table = Paged()
    assert [i["pk"] for i in StateStore(table).load_open()] == ["F#1", "F#2"]
    assert table.calls[1]["ExclusiveStartKey"] == {"pk": "F#1"}
