# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool (agent-managed write): put rendered report files to a local path or the report bucket."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CONTENT_TYPES = {
    ".md": "text/markdown",
    ".html": "text/html",
    ".csv": "text/csv",
    ".json": "application/json",
    ".svg": "image/svg+xml",
}


def write_report(
    artefacts: dict[str, str | bytes],
    *,
    local_dir: str = "",
    s3: Any = None,
    bucket: str = "",
    prefix: str = "",
) -> dict:
    """Write ``{relative_name: content}``. Local mode writes under ``local_dir``; hosted mode puts to S3."""
    written: list[str] = []
    for name, content in sorted(artefacts.items()):
        data = content.encode() if isinstance(content, str) else content
        if bucket and s3 is not None:
            key = f"{prefix.rstrip('/')}/{name}".lstrip("/")
            try:
                s3.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=data,
                    ContentType=_CONTENT_TYPES.get(Path(name).suffix, "application/octet-stream"),
                    # No ServerSideEncryption here: an explicit header would override the report bucket's
                    # default (customer-managed KMS key) for this object.
                )
            except Exception as exc:
                logger.error(  # logs the context for the operator, then re-raises to the caller  # nosemgrep: logging-error-without-handling
                    json.dumps(
                        {"event": "put_object_failed", "bucket": bucket, "key": key, "error": str(exc)[:200]}
                    )
                )
                raise
            written.append(f"s3://{bucket}/{key}")
        else:
            p = Path(local_dir) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            written.append(str(p))
    return {
        "written": written,
        "count": len(written),
        "destination": f"s3://{bucket}/{prefix}" if bucket else local_dir,
    }
