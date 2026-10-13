# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Private file helpers. Findings name accounts, users and keys, so output is owner-only."""

from __future__ import annotations

import os
from pathlib import Path


def make_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def write_private(path: Path, text: str) -> None:
    """Write atomically with owner-only permissions, so a crash never leaves a partial file."""
    make_private_dir(path.parent)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
    os.replace(temporary, path)
