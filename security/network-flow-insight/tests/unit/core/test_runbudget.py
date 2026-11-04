# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The per-invocation budget: tool calls and wall-clock time, with a message first and a hard stop after."""

import pytest

from network_flow_insight.core.runbudget import RunBudget, RunBudgetExceeded


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _budget(clock, max_calls=3, deadline=100.0, grace_calls=2, grace_seconds=10.0):
    b = RunBudget(max_calls, deadline, grace_calls=grace_calls, grace_seconds=grace_seconds, clock=clock)
    b.start()
    return b


def test_tool_calls_within_the_budget_are_allowed():
    b = _budget(Clock())
    assert [b.before_tool() for _ in range(3)] == [None, None, None]


def test_the_first_call_over_the_count_is_cancelled_with_a_message_for_the_model():
    b = _budget(Clock())
    for _ in range(3):
        b.before_tool()
    msg = b.before_tool()
    assert msg and "tool" in msg.lower() and "answer" in msg.lower()
    assert "3" in msg  # the limit is stated, so the model and the log agree


def test_a_model_that_keeps_asking_is_stopped():
    b = _budget(Clock(), grace_calls=2)
    for _ in range(3):
        b.before_tool()
    assert b.before_tool() and b.before_tool()  # two refusals are answered with the message
    with pytest.raises(RunBudgetExceeded):
        b.before_tool()  # the third is the hard stop


def test_the_deadline_cancels_tool_calls_even_under_the_count():
    clock = Clock()
    b = _budget(clock, max_calls=50, deadline=100.0)
    assert b.before_tool() is None
    clock.now += 101
    msg = b.before_tool()
    assert msg and "time" in msg.lower()


def test_a_model_call_is_allowed_until_the_deadline_plus_the_grace_period():
    clock = Clock()
    b = _budget(clock, deadline=100.0, grace_seconds=10.0)
    b.before_model()
    clock.now += 105  # past the deadline: the model may still write its final answer
    b.before_model()
    clock.now += 6  # past deadline + grace
    with pytest.raises(RunBudgetExceeded):
        b.before_model()


def test_start_gives_every_invocation_a_fresh_budget():
    clock = Clock()
    b = _budget(clock, max_calls=1, deadline=100.0)
    assert b.before_tool() is None
    assert b.before_tool() is not None  # over the count
    clock.now += 500  # and past the deadline
    b.start()
    assert b.before_tool() is None  # the count, the refusals and the clock all restarted
    b.before_model()


def test_a_zero_count_means_no_count_limit():
    b = _budget(Clock(), max_calls=0, deadline=100.0)
    assert all(b.before_tool() is None for _ in range(500))


def test_a_zero_deadline_means_no_time_limit():
    clock = Clock()
    b = _budget(clock, max_calls=5, deadline=0.0)
    clock.now += 1_000_000
    assert b.before_tool() is None
    b.before_model()


def test_with_both_limits_off_nothing_is_ever_refused():
    clock = Clock()
    b = _budget(clock, max_calls=0, deadline=0.0)
    clock.now += 1_000_000
    assert all(b.before_tool() is None for _ in range(500))
    b.before_model()


def test_a_negative_limit_is_rejected():
    with pytest.raises(ValueError):
        RunBudget(-1, 10.0)
    with pytest.raises(ValueError):
        RunBudget(1, -1.0)
