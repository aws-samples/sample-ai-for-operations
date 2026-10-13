# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Run one worker per account with bounded parallelism. One failing account never stops the run."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import Account, AccountResult

logger = logging.getLogger(__name__)

Worker = Callable[[Account], AccountResult]
Callback = Callable[[AccountResult], None]


def run_accounts(
    accounts: Iterable[Account],
    worker: Worker,
    max_workers: int,
    on_result: Callback | None = None,
) -> list[AccountResult]:
    """Return results in completion order. `on_result` is called from the calling thread as each
    account finishes, which is where checkpoints are written, so it needs no locking."""
    pending = list(accounts)
    results: list[AccountResult] = []
    if not pending:
        return results

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(pending)))) as pool:
        futures = {pool.submit(worker, account): account for account in pending}
        for future in as_completed(futures):
            account = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - an account failure must not abort the run
                logger.error(
                    "account_failed",
                    extra={"account_id": account.account_id, "error": type(exc).__name__},
                )
                result = AccountResult(
                    account=account,
                    status="failed",
                    reason=f"{type(exc).__name__}: {exc}",
                )
            results.append(result)
            if on_result is not None:
                on_result(result)
    return results
