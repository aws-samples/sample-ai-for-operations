# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Per-account checkpoints so a run interrupted by expired credentials can be resumed.

A checkpoint is reused only if the settings that influence scoring are unchanged, because the
findings inside it were scored with those settings."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import fields
from pathlib import Path

from .config import Config
from .models import AccountResult
from .output.files import make_private_dir, write_private
from .serialization import account_result_from_plain, to_plain

logger = logging.getLogger(__name__)

# Bump whenever the scoring rules or the stored fields change, so a resumed run never reuses
# results that were scored under older rules. 2: inactive access keys are rated as if re-enabled.
# 3: inactive API keys likewise, the bedrock:* canary needs all of its actions, and grants are
# detected from the resources the user's own policies name. 4: the result records when the
# credential report was generated.
FORMAT_VERSION = 4
# Settings that only affect presentation or run mechanics never invalidate a checkpoint.
_RUNTIME_ONLY = {
    "output_dir",
    "show_all",
    "unmask",
    "resume",
    "no_color",
    "log_level",
    "parallel_accounts",
    "mode",
    "role_name",
    "external_id",
    "scp_exception_principals",
    "approved_models",
}


class CheckpointError(RuntimeError):
    """The output directory cannot be used as requested. The CLI maps this to exit code 2."""


def config_fingerprint(config: Config) -> str:
    relevant = {
        f.name: to_plain(vars(config)[f.name])
        for f in fields(config)
        if f.name not in _RUNTIME_ONLY
    }
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()[:16]


class CheckpointStore:
    def __init__(self, output_dir: Path, fingerprint: str):
        self._directory = output_dir / ".checkpoints"
        self._fingerprint = fingerprint

    def prepare(self, resume: bool) -> None:
        existing = list(self._directory.glob("*.json")) if self._directory.exists() else []
        if existing and not resume:
            raise CheckpointError(
                f"{self._directory.parent} already holds results from an earlier run. "
                "Use --resume to continue it, or choose a different --output-dir."
            )
        make_private_dir(self._directory)

    def save(self, result: AccountResult) -> None:
        """Only complete accounts are saved. A failed or partial one is retried on resume, so a
        permission fixed in between is picked up."""
        if result.status != "ok":
            return
        payload = {
            "version": FORMAT_VERSION,
            "fingerprint": self._fingerprint,
            "result": to_plain(result),
        }
        write_private(self._path(result.account.account_id), json.dumps(payload, indent=2))

    def load(self, account_id: str) -> AccountResult | None:
        path = self._path(account_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("version") != FORMAT_VERSION:
                return None
            if payload.get("fingerprint") != self._fingerprint:
                logger.warning("checkpoint_stale", extra={"account_id": account_id})
                return None
            return account_result_from_plain(payload["result"])
        except (OSError, ValueError, KeyError) as exc:
            logger.warning(
                "checkpoint_unreadable",
                extra={"account_id": account_id, "error": type(exc).__name__},
            )
            return None

    def _path(self, account_id: str) -> Path:
        return self._directory / f"{account_id}.json"
