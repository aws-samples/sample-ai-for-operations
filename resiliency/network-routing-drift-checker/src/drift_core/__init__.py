# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Deterministic core of the network routing drift checker.

Collectors (data retrieval) fetch and normalize AWS API responses. Everything else
in this package is precision code: pure functions over snapshots, no LLM, no I/O.
"""
