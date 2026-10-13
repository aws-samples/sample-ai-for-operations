# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
from __future__ import annotations

import csv
import io
from collections.abc import Sequence
from pathlib import Path

from ..config import Config
from ..models import Finding
from .files import write_private
from .rows import CSV_COLUMNS, csv_row, csv_safe, protect


def render_csv(findings: Sequence[Finding], config: Config) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for finding in findings:
        row = csv_row(finding, config)
        writer.writerow({column: csv_safe(protect(value, config)) for column, value in row.items()})
    return buffer.getvalue()


def write_csv(path: Path, findings: Sequence[Finding], config: Config) -> None:
    write_private(path, render_csv(findings, config))
