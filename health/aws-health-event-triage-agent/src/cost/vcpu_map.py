# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: map_instance_class_to_vcpu.

Pure lookup against a checked-in map (config/vcpu-map.json). No AWS calls,
no model call. Returns None for instance classes not in the map so callers
can treat the resource as non-projectable rather than guessing.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_MAP_PATH = Path(__file__).parents[2] / "config" / "vcpu-map.json"

_vcpu_cache: dict[str, int] | None = None


def _load_map() -> dict[str, int]:
    global _vcpu_cache
    if _vcpu_cache is not None:
        return _vcpu_cache
    path = Path(os.environ.get("VCPU_MAP_PATH", str(_DEFAULT_MAP_PATH)))
    try:
        with open(path, encoding='utf-8') as f:
            _vcpu_cache = json.load(f)
        logger.info("Loaded %d vCPU map entries from %s", len(_vcpu_cache), path)
    except FileNotFoundError:
        _vcpu_cache = {}
    except Exception as exc:
        logger.warning("Could not load vCPU map from %s: %s", path, exc)
        _vcpu_cache = {}
    return _vcpu_cache


def map_instance_class_to_vcpu(instance_class: str) -> int | None:
    """Return the vCPU count for an RDS/EC2-style instance class.

    Args:
        instance_class: The instance class string (e.g. "db.r5.large").

    Returns:
        The vCPU count as an int, or None if the instance class is not in
        the checked-in map. Callers MUST treat None as "cannot project cost
        for this resource" rather than assuming a default.
    """
    vmap = _load_map()
    return vmap.get(instance_class)
