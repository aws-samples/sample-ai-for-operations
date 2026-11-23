# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Framework-free contracts for persisted assessment session state.

The deterministic core supports a local JSON implementation for profile v1 and
an AgentCore Memory implementation for profile v2. Keeping the record and
protocol here lets both adapters share a contract without importing Strands,
Amazon Bedrock model clients, or scoring logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SessionAnswer:
    """One persisted answer to a fixed assessment question."""

    question_id: str
    answer_value: str
    source: str
    timestamp: str
    changed: bool


class SessionStore(Protocol):
    """Persistence boundary used by deterministic assessment workflows."""

    def list_answers(self) -> tuple[SessionAnswer, ...]:
        """Return saved answers in stable question-ID order."""
        ...

    def set_answer(
        self, question_id: str, answer_value: str, source: str = "cli"
    ) -> SessionAnswer:
        """Persist one answer and mark derived assessment state stale."""
        ...

    def as_business_context_answers(self) -> tuple[dict[str, object], ...]:
        """Return answers in the canonical business-context payload shape."""
        ...

    def mark_derived_current(self, assessment_id: str) -> None:
        """Record that derived output reflects the latest saved answers."""
        ...
