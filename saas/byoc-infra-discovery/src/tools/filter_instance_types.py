# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Precision tool: filter instance types by exact numeric/architecture criteria.

Pure code, no LLM, no AWS calls. Applies exact comparisons so the agent never
filters or compares numbers in natural language.
"""

from typing import Optional

from strands import tool


def filter_instance_types_impl(
    types: list,
    min_vcpu: Optional[int] = None,
    min_memory_mib: Optional[int] = None,
    arch: Optional[str] = None,
) -> dict:
    """Core logic (testable without the Strands runtime)."""
    if not isinstance(types, list):
        return {
            "error": True,
            "error_type": "invalid_input",
            "message": "types must be a list",
        }

    arch_norm = arch.strip().lower() if isinstance(arch, str) and arch.strip() else None
    matches = []
    for it in types:
        if not isinstance(it, dict):
            continue
        vcpu = it.get("vcpu")
        mem = it.get("memory_mib")
        it_arch = it.get("arch")

        if min_vcpu is not None and (vcpu is None or vcpu < min_vcpu):
            continue
        if min_memory_mib is not None and (mem is None or mem < min_memory_mib):
            continue
        if arch_norm is not None:
            if not it_arch or it_arch.strip().lower() != arch_norm:
                continue
        matches.append(it)

    return {"matches": matches, "match_count": len(matches)}


@tool
def filter_instance_types(
    types: list,
    min_vcpu: Optional[int] = None,
    min_memory_mib: Optional[int] = None,
    arch: Optional[str] = None,
) -> dict:
    """Filter instance types by minimum vCPU, minimum memory, and/or architecture.

    Operates on the list returned by resolve_instance_types. Comparisons are
    exact — use this instead of filtering or comparing numbers in natural
    language. Types whose relevant attribute is unknown (None) are excluded when
    that criterion is applied.

    Args:
        types: list of instance-type dicts.
        min_vcpu: minimum vCPU count (inclusive).
        min_memory_mib: minimum memory in MiB (inclusive).
        arch: required architecture (e.g. "x86_64", "arm64").

    Returns:
        {"matches": [...], "match_count": <int>}
    """
    return filter_instance_types_impl(types, min_vcpu, min_memory_mib, arch)
