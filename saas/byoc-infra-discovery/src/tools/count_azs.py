# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Precision tool: exact count of availability zones.

Pure code, no LLM, no AWS calls. Counts unique AZ IDs so the agent never has to
count in natural language.
"""

from strands import tool


def count_azs_impl(az_list: list) -> dict:
    """Core logic (testable without the Strands runtime)."""
    if not isinstance(az_list, list):
        return {"error": True, "error_type": "invalid_input", "message": "az_list must be a list"}

    ids: set[str] = set()
    for entry in az_list:
        if isinstance(entry, dict) and entry.get("az_id"):
            ids.add(entry["az_id"])
        elif isinstance(entry, str) and entry.strip():
            ids.add(entry.strip())
    return {"count": len(ids)}


@tool
def count_azs(az_list: list) -> dict:
    """Count the unique availability zones in a list.

    Accepts either a list of AZ-ID strings or a list of {"az_id": ...} dicts (the
    shape returned by resolve_availability_zones). Use this instead of counting
    in natural language.

    Args:
        az_list: list of AZ IDs or AZ dicts.

    Returns:
        {"count": <int>}
    """
    return count_azs_impl(az_list)
