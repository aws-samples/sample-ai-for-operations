# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: AWS public IP ranges over HTTPS (cached for a day)."""

from __future__ import annotations

import json
from pathlib import Path

from ..core.fileio import read_text
from ..core.ipranges import IpRanges, fetch_document


def get_ip_ranges(url: str, cache_dir: str = "", local_file: str = "", s3: object = None) -> IpRanges:
    doc = json.loads(read_text(local_file, s3)) if local_file else fetch_document(url, cache_dir or None)
    return IpRanges(doc)


def default_cache_dir() -> str:
    return str(Path.home() / ".cache" / "network-flow-insight")
