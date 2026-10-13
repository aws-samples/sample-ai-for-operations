# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
import threading
import time

from bedrock_permissions_audit.accounts import AssumeRoleError
from bedrock_permissions_audit.models import Account, AccountResult
from bedrock_permissions_audit.runner import run_accounts


def ok(account):
    return AccountResult(account=account, status="ok", principals_evaluated=1)


def accounts(n):
    return [Account(f"{i:012d}") for i in range(n)]


def test_every_account_is_processed_once():
    results = run_accounts(accounts(10), ok, max_workers=4)
    assert sorted(r.account.account_id for r in results) == [a.account_id for a in accounts(10)]
    assert all(r.status == "ok" for r in results)


def test_e1_one_failing_account_does_not_stop_the_others():
    def worker(account):
        if account.account_id == "000000000001":
            raise AssumeRoleError("Cannot assume role: AccessDenied")
        return ok(account)

    results = run_accounts(accounts(3), worker, max_workers=2)

    failed = [r for r in results if r.status == "failed"]
    assert len(results) == 3
    assert len(failed) == 1
    assert failed[0].account.account_id == "000000000001"
    assert "AccessDenied" in failed[0].reason


def test_unexpected_exception_is_reported_not_raised():
    def worker(account):
        raise KeyError("boom")

    (result,) = run_accounts(accounts(1), worker, max_workers=1)
    assert result.status == "failed"
    assert result.reason.startswith("KeyError")


def test_parallelism_is_bounded():
    lock = threading.Lock()
    running = 0
    peak = 0

    def worker(account):
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.02)
        with lock:
            running -= 1
        return ok(account)

    run_accounts(accounts(12), worker, max_workers=3)
    assert 1 < peak <= 3


def test_callback_runs_on_the_calling_thread_for_each_result():
    caller = threading.get_ident()
    seen = []

    def on_result(result):
        seen.append((threading.get_ident(), result.account.account_id))

    run_accounts(accounts(5), ok, max_workers=3, on_result=on_result)

    assert len(seen) == 5
    assert {thread for thread, _ in seen} == {caller}


def test_empty_input_returns_empty_list():
    assert run_accounts([], ok, max_workers=4) == []
