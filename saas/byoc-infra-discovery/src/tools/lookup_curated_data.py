# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tool: curated (no-API) datasets bundled with the agent.

Datasets that have no public API and are maintained as versioned JSON files:
  * eni_max_pods            -- ENI max pods per instance type
  * eks_ecr_registries      -- Amazon EKS add-on ECR registry account per region
  * s3_location_constraints -- Amazon S3 CreateBucket LocationConstraint per region
  * eks_eol_dates           -- Amazon EKS Kubernetes version end-of-support dates

Each file carries _source and _last_updated provenance. Pure code, no LLM.
"""

import json
import os
from functools import lru_cache
from typing import Optional

from strands import tool

from tools._common import CONFIDENCE_HIGH, SOURCE_CURATED

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

_VALID_DATASETS = {
    "eni_max_pods",
    "eks_ecr_registries",
    "s3_location_constraints",
    "eks_eol_dates",
}


@lru_cache(maxsize=None)
def _load(dataset: str) -> dict:
    path = os.path.join(_DATA_DIR, f"{dataset}.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise FileNotFoundError(f"curated dataset '{dataset}' unavailable: {exc}") from exc


def lookup_curated_data_impl(dataset: str, key: Optional[str] = None) -> dict:
    """Core logic (testable without the Strands runtime)."""
    if not isinstance(dataset, str) or dataset not in _VALID_DATASETS:
        return {
            "error": True,
            "error_type": "invalid_dataset",
            "message": f"Unknown curated dataset '{dataset}'. "
            f"Valid: {sorted(_VALID_DATASETS)}",
        }

    doc = _load(dataset)
    data = doc.get("data", {})
    provenance = {
        "source": SOURCE_CURATED,
        "source_url": doc.get("_source"),
        "last_updated": doc.get("_last_updated"),
        "confidence": CONFIDENCE_HIGH,
    }

    if key is None:
        return {"dataset": dataset, "value": data, **provenance}

    if key not in data:
        return {
            "dataset": dataset,
            "key": key,
            "value": None,
            "found": False,
            **provenance,
        }
    return {"dataset": dataset, "key": key, "value": data[key], "found": True, **provenance}


@tool
def lookup_curated_data(dataset: str, key: Optional[str] = None) -> dict:
    """Look up a value from a curated (no public API) dataset.

    Valid datasets: "eni_max_pods" (key = instance type), "eks_ecr_registries"
    (key = region), "s3_location_constraints" (key = region), "eks_eol_dates"
    (key = Kubernetes version like "1.30"). Omit key to return the whole dataset.

    Args:
        dataset: one of the valid curated dataset names.
        key: optional lookup key within the dataset.

    Returns:
        {"dataset", "value", "source", "source_url", "last_updated",
         "confidence"} plus {"key", "found"} when a key is given, or a structured
        error object for an invalid dataset.
    """
    return lookup_curated_data_impl(dataset, key)
