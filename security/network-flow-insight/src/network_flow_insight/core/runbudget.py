# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""A budget for one agent invocation: a number of tool calls and an amount of wall-clock time.

The agent loop is model-driven, so nothing in the loop itself ends it except the model. An unattended run
(a schedule) needs an upper bound. This module holds only the bookkeeping, with an injectable clock so it is tested
without a model; ``agent.py`` wires it to the agent's hooks.

Behaviour once a limit is reached: the first refusals return a message that the hook gives back to the model in place
of the tool result (it should stop calling tools and answer). If the model ignores it, ``grace_calls`` refusals later
the invocation stops with ``RunBudgetExceeded``. A model call that would start later than the deadline plus
``grace_seconds`` stops it too; the grace lets a model that obeyed the message write its final answer.
"""

from __future__ import annotations

import time
from collections.abc import Callable


class RunBudgetExceeded(RuntimeError):
    """The model kept asking for tools after the budget was used up, or ran far past the deadline."""


class RunBudget:
    def __init__(
        self,
        max_tool_calls: int,
        deadline_seconds: float,
        *,
        grace_calls: int = 5,
        grace_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """A limit of 0 disables it. Negative limits are a configuration error."""
        if max_tool_calls < 0 or deadline_seconds < 0:
            raise ValueError("run budget limits must be zero (off) or positive")
        self.max_tool_calls = max_tool_calls
        self.deadline_seconds = deadline_seconds
        self.grace_calls = grace_calls
        self.grace_seconds = grace_seconds
        self._clock = clock
        self.start()

    def start(self) -> None:
        """Begin a new invocation: the count, the refusals and the clock all restart."""
        self._started = self._clock()
        self._calls = 0
        self._refusals = 0

    def _elapsed(self) -> float:
        return self._clock() - self._started

    def _reason(self) -> str | None:
        if self.max_tool_calls and self._calls >= self.max_tool_calls:
            return f"{self.max_tool_calls} tool calls"
        if self.deadline_seconds and self._elapsed() > self.deadline_seconds:
            return f"{self.deadline_seconds:g} seconds of run time"
        return None

    def before_tool(self) -> str | None:
        """Return None to allow the call, or a message that replaces the tool result.

        Raises ``RunBudgetExceeded`` when the model has been refused more than ``grace_calls`` times.
        """
        reason = self._reason()
        if reason is None:
            self._calls += 1
            return None
        self._refusals += 1
        if self._refusals > self.grace_calls:
            raise RunBudgetExceeded(f"run budget of {reason} used up and the model kept requesting tools")
        return (
            f"Tool budget used up ({reason}). Do not call any more tools. "
            "Answer now from the results you already have and say what is missing."
        )

    def before_model(self) -> None:
        """Raise if a model call would start well after the deadline."""
        if self.deadline_seconds and self._elapsed() > self.deadline_seconds + self.grace_seconds:
            raise RunBudgetExceeded(f"run time passed {self.deadline_seconds:g} seconds plus the grace period")
