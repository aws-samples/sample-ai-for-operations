# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""S3 run artifacts and the intent file (design.md D§2.1). Thin I/O; errors are logged with context."""

from __future__ import annotations

import json
import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from drift_core.logging_util import get_logger, log_event

_log = get_logger(__name__)
_MISSING = {"NoSuchKey", "404", "NotFound"}


class ArtifactError(RuntimeError):
    """A run artifact could not be read or written. The run fails loudly (alarmed), never silently."""


class Artifacts:
    def __init__(self, s3: Any, bucket: str, run_id: str) -> None:
        self._s3, self.bucket, self.run_id = s3, bucket, run_id

    def key(self, name: str) -> str:
        return f"runs/{self.run_id}/{name}"

    def uri(self, name: str) -> str:
        return f"s3://{self.bucket}/{self.key(name)}"

    def put_json(self, name: str, obj: Any) -> str:
        return self._put(name, json.dumps(obj, sort_keys=True, default=str).encode("utf-8"), "application/json")

    def put_text(self, name: str, text: str) -> str:
        return self._put(name, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _put(self, name: str, body: bytes, content_type: str) -> str:
        key = self.key(name)
        try:
            self._s3.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType=content_type)
        except (ClientError, BotoCoreError) as exc:
            log_event(_log, "artifact_write_failed", logging.ERROR, bucket=self.bucket, key=key,
                      error=type(exc).__name__)
            raise ArtifactError(f"could not write s3://{self.bucket}/{key}") from exc
        return key

    def get_json(self, name: str) -> Any:
        key = self.key(name)
        try:
            body = self._s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except (ClientError, BotoCoreError) as exc:
            log_event(_log, "artifact_read_failed", logging.ERROR, bucket=self.bucket, key=key,
                      error=type(exc).__name__)
            raise ArtifactError(f"could not read s3://{self.bucket}/{key}") from exc
        return json.loads(body)


def read_intent(s3: Any, bucket: str, key: str) -> tuple[str, str | None, str | None, str | None]:
    """Return (status, text, version_id, error). status: 'found' | 'absent' | 'unreadable'. Never raises."""
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        return "found", resp["Body"].read().decode("utf-8"), resp.get("VersionId"), None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _MISSING:
            return "absent", None, None, None
        log_event(_log, "intent_read_failed", logging.WARNING, bucket=bucket, key=key, error=code)
        return "unreadable", None, None, code or "ClientError"
    except (BotoCoreError, UnicodeDecodeError) as exc:
        log_event(_log, "intent_read_failed", logging.WARNING, bucket=bucket, key=key, error=type(exc).__name__)
        return "unreadable", None, None, type(exc).__name__
