# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Inventory providers: A (EC2), B (AWS Config aggregator), C (JSON file), D (none; heuristics)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..fileio import read_text
from . import config_agg, ec2
from .model import Inventory, InventoryError, validate_document

__all__ = ["Inventory", "InventoryError", "load_file", "load_provider", "validate_document"]


def load_file(path: str | Path, s3: Any = None) -> Inventory:
    """Provider C. ``path`` may be a local file or an ``s3://`` URI."""
    try:
        doc = json.loads(read_text(str(path), s3))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot read inventory file {path}: {exc}") from exc
    return Inventory(doc)


def load_provider(
    provider: str,
    *,
    session: Any = None,
    region: str = "",
    regions: list[str] | None = None,
    inventory_file: str = "",
    aggregator: str = "",
) -> tuple[str, Inventory | None, str]:
    """Resolve the provider to use.

    Returns ``(provider_letter, inventory_or_None, note)``. ``auto`` prefers a file, then a Config
    aggregator, then EC2 in the current account, then none (provider D).
    """
    order = {
        "auto": ["file", "config", "ec2"],
        "file": ["file"],
        "config": ["config"],
        "ec2": ["ec2"],
        "none": [],
    }
    if provider not in order:
        raise InventoryError(f"unknown inventory provider {provider!r}; use auto, ec2, config, file or none")
    notes: list[str] = []
    for p in order[provider]:
        try:
            if p == "file":
                if not inventory_file:
                    continue
                return (
                    "C",
                    load_file(
                        inventory_file,
                        session.client("s3")
                        if session is not None and inventory_file.startswith("s3://")
                        else None,
                    ),
                    f"file {inventory_file}",
                )
            if p == "config":
                if not aggregator or session is None:
                    continue
                inv = Inventory(
                    config_agg.collect(session.client("config", region_name=region or None), aggregator)
                )
                if not inv.interfaces:
                    notes.append("config aggregator returned no network interfaces")
                    continue
                return "B", inv, f"AWS Config aggregator {aggregator}"
            if p == "ec2":
                if session is None:
                    continue
                inv = Inventory(ec2.collect(session, regions or [region]))
                if not inv.interfaces:
                    notes.append("EC2 returned no network interfaces in this account")
                    continue
                return "A", inv, "Amazon EC2 in the current account"
        except Exception as exc:  # provider failures degrade to the next option, and are reported
            if provider != "auto":
                raise
            notes.append(f"provider {p} unavailable: {type(exc).__name__}: {str(exc)[:160]}")
    return "D", None, "; ".join(notes) or "no inventory provider configured"
