# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Read small configuration files from a local path or an ``s3://`` URI (hosted mode keeps them in S3)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def read_text(location: str, s3: Any = None) -> str:
    if location.startswith("s3://"):
        bucket, _, key = location[5:].partition("/")
        if not bucket or not key:
            raise ValueError(f"invalid S3 URI: {location!r}")
        if s3 is None:
            import boto3

            s3 = boto3.client("s3")
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    return Path(location).read_text()
