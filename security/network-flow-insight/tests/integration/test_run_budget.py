# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The run budget on the real agent loop (scripted model): cancel first, hard stop after, fresh budget per invocation."""

import argparse

import pytest

from network_flow_insight import agent as agent_mod
from network_flow_insight import cli
from network_flow_insight.config import load_settings
from network_flow_insight.core.runbudget import RunBudgetExceeded
from network_flow_insight.demo import estate as E
from network_flow_insight.toolset import ToolSession
from tests.integration.scripted_model import ScriptedModel

B = E.WINDOW_B


def _probe():
    return ("tool", "probe", {"first_day": B[0], "last_day": B[1]})


def _tool_result_texts(agent):
    out = []
    for msg in agent.messages:
        for block in msg.get("content", []):
            res = block.get("toolResult")
            if res:
                out.append(" ".join(part.get("text", "") for part in res.get("content", [])))
    return out


def test_defaults_and_environment_overrides():
    s = load_settings(env={}, toml_path=None)
    assert (s.max_tool_calls, s.run_deadline_seconds) == (60, 780)
    s = load_settings(env={"NFI_MAX_TOOL_CALLS": "25", "NFI_RUN_DEADLINE_SECONDS": "600"}, toml_path=None)
    assert (s.max_tool_calls, s.run_deadline_seconds) == (25, 600)


def test_calls_over_the_budget_are_cancelled_and_the_model_can_still_answer(make_analysis):
    a, _ = make_analysis("full")
    settings = a.s.with_overrides(max_tool_calls=2, run_deadline_seconds=0)
    model = ScriptedModel([_probe(), _probe(), _probe(), _probe(), ("text", "Answer from what I have.")])
    agent = agent_mod.create_agent(ToolSession(a), settings, model=model)
    result = agent("Map the traffic.")
    assert "Answer from what I have." in str(result)
    texts = _tool_result_texts(agent)
    assert len(texts) == 4
    assert [("budget" in t.lower()) for t in texts] == [False, False, True, True]


def test_a_model_that_ignores_the_message_is_stopped(make_analysis):
    a, _ = make_analysis("full")
    settings = a.s.with_overrides(max_tool_calls=1, run_deadline_seconds=0)
    model = ScriptedModel([_probe() for _ in range(20)])
    agent = agent_mod.create_agent(ToolSession(a), settings, model=model)
    with pytest.raises(RunBudgetExceeded):
        agent_mod.ask(agent, "Map the traffic.")  # Strands wraps hook errors; ask() hands back the real one
    assert len(model.steps) > 5  # it stopped long before the script ran out


def test_ask_leaves_other_errors_alone(make_analysis):
    a, _ = make_analysis("full")
    model = ScriptedModel([("raise", "model unavailable")])
    agent = agent_mod.create_agent(ToolSession(a), a.s, model=model)
    with pytest.raises(Exception) as raised:  # noqa: PT011
        agent_mod.ask(agent, "go")
    assert not isinstance(raised.value, RunBudgetExceeded)


def test_local_chat_ends_with_a_clear_message_when_the_budget_is_used_up(make_analysis, monkeypatch, capsys):
    a, _ = make_analysis("full")
    settings = a.s.with_overrides(max_tool_calls=1, run_deadline_seconds=0)
    ts = ToolSession(a)
    model = ScriptedModel([_probe() for _ in range(20)])
    monkeypatch.setattr(cli, "_settings", lambda args: settings)
    monkeypatch.setattr(cli, "_window", lambda args, s: B)
    monkeypatch.setattr(cli, "_aws_session", lambda args, s, first, last: ts)
    monkeypatch.setattr(agent_mod, "build_model", lambda s: model)
    monkeypatch.setattr("builtins.input", lambda prompt="": "map it")
    assert cli.cmd_chat(argparse.Namespace(remote=False)) == 1
    assert "run budget" in capsys.readouterr().out.lower()


def test_a_scheduled_run_that_hits_the_budget_still_renders_the_report(make_analysis):
    a, est = make_analysis("full")
    settings = a.s.with_overrides(max_tool_calls=1, run_deadline_seconds=0)
    ts = ToolSession(a)
    model = ScriptedModel([_probe() for _ in range(20)])
    out = agent_mod.run_scheduled(ts, settings, "describe", B[0], B[1], model=model)
    assert out["agent_error"] == "RunBudgetExceeded"
    assert out["fallback"] and ts.findings is not None
    gt = est.truth["by_window"]["B"]
    assert {r["path_class"]: r["bytes"] for r in ts.findings["path_volume"]["by_path"]["rows"]} == gt["path_bytes"]


def test_every_invocation_gets_a_fresh_budget(make_analysis):
    a, _ = make_analysis("full")
    settings = a.s.with_overrides(max_tool_calls=2, run_deadline_seconds=0)
    model = ScriptedModel([_probe(), _probe(), ("text", "first"), _probe(), _probe(), ("text", "second")])
    agent = agent_mod.create_agent(ToolSession(a), settings, model=model)
    assert "first" in str(agent("one"))
    assert "second" in str(agent("two"))
    assert not [t for t in _tool_result_texts(agent) if "budget" in t.lower()]


def test_limits_of_zero_leave_the_loop_unbounded(make_analysis):
    a, _ = make_analysis("full")
    settings = a.s.with_overrides(max_tool_calls=0, run_deadline_seconds=0)
    model = ScriptedModel([_probe() for _ in range(8)] + [("text", "done")])
    agent = agent_mod.create_agent(ToolSession(a), settings, model=model)
    assert "done" in str(agent("go"))
    assert not [t for t in _tool_result_texts(agent) if "budget" in t.lower()]
