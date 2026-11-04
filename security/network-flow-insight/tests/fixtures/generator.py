# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Test-facing entry point for the synthetic estate generator (implementation lives in the package
so that ``nfi demo`` works from a pip install)."""

from network_flow_insight.demo.generator import TIERS, Estate, generate  # noqa: F401
