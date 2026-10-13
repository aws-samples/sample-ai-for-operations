# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""One audit run, start to finish: discover accounts, audit each, write the outputs."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import boto3

from .accounts import Discovery, SessionFactory, discover
from .audit import EvaluatorFactory, make_worker
from .checkpoint import CheckpointStore, config_fingerprint
from .config import Config, resolve_output_dir
from .evaluator import SimulatorEvaluator
from .models import Account, AccountResult, Finding, RunSummary
from .output.csv_writer import write_csv
from .output.json_writer import write_json
from .output.remediation import write_remediation
from .runner import run_accounts
from .summary import collect_findings, summarize

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_ALL_FAILED = 3


@dataclass(frozen=True)
class RunOutcome:
    exit_code: int
    summary: RunSummary
    findings: list[Finding]
    output_dir: Path


def run_audit(
    config: Config,
    session: boto3.Session | None = None,
    now: datetime | None = None,
    evaluator_factory: EvaluatorFactory = SimulatorEvaluator,
) -> RunOutcome:
    """Raises DiscoveryError or CheckpointError for problems found before any account is
    audited; the CLI turns those into exit code 2."""
    session = session or boto3.Session()
    started = now or datetime.now(UTC)

    discovery = discover(config, session)
    output_dir = resolve_output_dir(config, started)
    store = CheckpointStore(output_dir, config_fingerprint(config))
    store.prepare(config.resume)

    reused, pending = _split_by_checkpoint(discovery, store, config.resume)
    logger.info(
        "run_started",
        extra={
            "mode": discovery.mode,
            "accounts": len(discovery.accounts),
            "resumed": len(reused),
            "output_dir": str(output_dir),
        },
    )

    worker = make_worker(
        config, SessionFactory(config, session, discovery), started, evaluator_factory
    )
    fresh = run_accounts(pending, worker, config.parallel_accounts, on_result=store.save)
    results = [*reused, *fresh]

    finished = datetime.now(UTC) if now is None else now
    notices = [discovery.notice] if discovery.notice else []
    if reused:
        notices.append(f"Resumed: {len(reused)} account(s) were taken from an earlier run.")
    summary = summarize(discovery.mode, started, finished, results, config, notices)
    findings = collect_findings(results, config)

    write_csv(output_dir / "findings.csv", findings, config)
    write_json(output_dir / "findings.json", findings, summary, config)
    write_remediation(output_dir / "remediation", config)

    all_failed = bool(results) and summary.accounts_scanned == 0
    return RunOutcome(EXIT_ALL_FAILED if all_failed else EXIT_OK, summary, findings, output_dir)


def _split_by_checkpoint(
    discovery: Discovery, store: CheckpointStore, resume: bool
) -> tuple[list[AccountResult], list[Account]]:
    if not resume:
        return [], list(discovery.accounts)
    reused: list[AccountResult] = []
    pending: list[Account] = []
    for account in discovery.accounts:
        saved = store.load(account.account_id)
        if saved is None:
            pending.append(account)
        else:
            reused.append(saved)
    return reused, pending
