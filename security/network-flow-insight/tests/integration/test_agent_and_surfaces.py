# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Agent loop with a scripted model, MCP surface, hosted handler and demo CLI: E7 parity, E10a, E12."""

import asyncio
import json

import pytest

from network_flow_insight import agent as agent_mod
from network_flow_insight import agentcore_app, cli
from network_flow_insight.config import Settings
from network_flow_insight.demo import estate as E
from network_flow_insight.mcp_server import build_server
from network_flow_insight.toolset import ToolSession, tool_methods
from tests.integration.scripted_model import ScriptedModel

B = E.WINDOW_B


def _script(first=B[0], last=B[1]):
    return [
        ("tool", "probe", {"first_day": first, "last_day": last}),
        ("tool", "describe", {"first_day": first, "last_day": last, "compare_previous": True}),
        ("tool", "get_section", {"name": "reconciliation"}),
        (
            "tool",
            "render_report",
            {"narrative": {"summary": "NAT traffic reconciled on the leg check and the metrics."}},
        ),
        ("text", "Report written."),
    ]


def test_agent_runs_the_method_through_tools_only(make_analysis, tmp_path):
    a, est = make_analysis("full")
    a.s = a.s.with_overrides(reports_dir=str(tmp_path))
    ts = ToolSession(a)
    model = ScriptedModel(_script())
    agent = agent_mod.create_agent(ts, a.s, model=model)
    out = agent("Produce the traffic map")
    assert "Report written" in str(out)
    assert set(model.seen_tool_names) == {m.__name__ for m in tool_methods(ts)}
    # the system prompt carries the number rule, and no inline prompt strings are used
    assert "never count" in model.system_prompts[0].lower()
    assert ts.findings is not None
    assert (tmp_path / f"{B[0]}_{B[1]}" / "report.md").exists()
    md = (tmp_path / f"{B[0]}_{B[1]}" / "report.md").read_text()
    assert "Interpretation (written by the model" in md


def test_narrative_with_ungrounded_figures_is_left_out(make_analysis, tmp_path):
    a, _ = make_analysis("full")
    a.s = a.s.with_overrides(reports_dir=str(tmp_path))
    ts = ToolSession(a)
    ts.describe(*B, compare_previous=False)
    res = ts.render_report(
        {"nat": "NAT carried 987654321 bytes, a 77% share.", "summary": "Reconciliation was reconciled."},
    )
    md = (tmp_path / f"{B[0]}_{B[1]}" / "report.md").read_text()
    assert "987654321" not in md and "left out" in md and "Reconciliation was reconciled" in md
    assert res["written"]


def test_guardrail_is_required_unless_explicitly_waived():
    with pytest.raises(agent_mod.GuardrailMissing):
        agent_mod.build_model(Settings())


def test_mcp_server_parity_with_local_session(make_analysis):
    a, _ = make_analysis("full")
    local = ToolSession(a).describe(*B, compare_previous=False)

    a2, _ = make_analysis("full")
    server = build_server(ToolSession(a2))
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == {m.__name__ for m in tool_methods(ToolSession(a2))}
    res = asyncio.run(
        server.call_tool("describe", {"first_day": B[0], "last_day": B[1], "compare_previous": False})
    )
    payload = json.loads(res.content[0].text) if hasattr(res, "content") else json.loads(res[0].text)
    assert payload["headlines"] == local["headlines"]
    assert payload["reconciliation"] == local["reconciliation"]
    assert payload["scan"] == local["scan"]


def test_hosted_handler_scheduled_run_writes_report_and_matches_local(make_analysis, tmp_path, monkeypatch):
    a, est = make_analysis("full")
    a.s = a.s.with_overrides(reports_dir=str(tmp_path), report_bucket="")
    ts = ToolSession(a)
    model = ScriptedModel(
        [
            ("tool", "describe", {"first_day": B[0], "last_day": B[1], "compare_previous": False}),
            ("text", "Scheduled run complete."),
        ]
    )
    out = agentcore_app.handle(
        {"mode": "describe", "first_day": B[0], "last_day": B[1]},
        a.s,
        model=model,
        session_factory=lambda: ts,
    )
    assert out["mode"] == "describe" and "Scheduled run complete" in out["summary"]
    gt = est.truth["by_window"]["B"]
    assert {r["path_class"]: r["bytes"] for r in ts.findings["path_volume"]["by_path"]["rows"]} == gt[
        "path_bytes"
    ]


def test_hosted_handler_validates_payloads():
    for bad in ({"mode": "delete"}, {"mode": "chat"}, {"mode": "describe", "first_day": "yesterday"}):
        with pytest.raises(ValueError):
            agentcore_app.validate_payload(bad)
    assert agentcore_app.validate_payload({"mode": "drift"})["mode"] == "drift"


def test_e10a_demo_renders_complete_report_without_credentials(tmp_path, monkeypatch, capsys):
    import boto3

    for k in list(__import__("os").environ):
        if k.startswith("AWS_"):
            monkeypatch.delenv(k)

    def boom(*a, **k):
        raise AssertionError("demo mode must not create AWS clients")

    monkeypatch.setattr(boto3, "client", boom)
    monkeypatch.setattr(boto3.session.Session, "client", boom)
    rc = cli.main(["demo", "--out", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Reconciliation: reconciled" in out
    run = tmp_path / f"{B[0]}_{B[1]}"
    assert {p.name for p in run.iterdir()} == {"report.md", "report.html", "diagram.svg", "data"}
    f = json.loads((run / "data" / "findings.json").read_text())
    from network_flow_insight.demo.generator import generate

    est = generate(tmp_path / "gt", "full")
    gt = est.truth["by_window"]["B"]
    assert {r["path_class"]: r["bytes"] for r in f["path_volume"]["by_path"]["rows"]} == gt["path_bytes"]
    assert f["nat"]["scope"]["translated"]["total_bytes"] == gt["nat_out_bytes"] + gt["nat_in_bytes"]
    assert (run / "data" / "edges.csv").read_text().startswith("consumer,")
    assert "<svg" in (run / "diagram.svg").read_text()


@pytest.mark.parametrize(
    "tier,inventory,expected",
    [("basic", False, "basic-no-inventory"), ("enhanced", True, "enhanced"), ("full", True, "full")],
)
def test_demo_tiers_produce_different_reports(tier, inventory, expected, make_analysis):
    a, est = make_analysis(tier, inventory=inventory)
    f = a.describe(*B, compare_previous=False)
    assert f["meta"]["tier"] == expected
    gt = est.truth["by_window"]["B"]
    if inventory:
        assert {r["path_class"]: r["bytes"] for r in f["path_volume"]["by_path"]["rows"]} == gt["path_bytes"]
    else:
        # provider D: no route tables, so NAT / gateway-endpoint / IGW cannot be told apart, and says so
        classes = {r["path_class"] for r in f["path_volume"]["by_path"]["rows"]}
        assert "internet-nat" not in classes and "internet-unresolved" in classes
        assert f["tier"]["sections"]["endpoint_effectiveness"]["status"] == "unavailable"
        assert f["endpoint_effectiveness"]["status"] == "unavailable"
        total = f["path_volume"]["by_path"]["total"]["bytes"]
        assert total == sum(r["bytes"] for r in f["path_volume"]["by_path"]["rows"])


def test_demo_estate_command_writes_uploadable_layout(tmp_path, capsys):
    assert cli.main(["demo-estate", str(tmp_path / "e"), "--tier", "basic"]) == 0
    assert "aws s3 sync" in capsys.readouterr().out
    assert next((tmp_path / "e" / "s3" / "AWSLogs").iterdir()).name in (E.ACCT_A, E.ACCT_B)
    assert (tmp_path / "e" / "ground_truth.json").exists() and (tmp_path / "e" / "inventory.json").exists()


def test_hosted_report_in_s3_keeps_the_model_interpretation(make_analysis, tmp_path, monkeypatch):
    import boto3

    puts = {}

    class S3Put:
        def put_object(self, Bucket, Key, Body, **kw):  # noqa: N803
            puts[Key] = Body

    monkeypatch.setattr(boto3, "client", lambda name, *a, **k: S3Put())
    a, _ = make_analysis("full")
    a.s = a.s.with_overrides(report_bucket="rb")
    ts = ToolSession(a)
    model = ScriptedModel(
        [
            ("tool", "describe", {"first_day": B[0], "last_day": B[1], "compare_previous": False}),
            ("tool", "render_report", {"narrative": {"summary": "NAT traffic reconciled on the leg check."}}),
            ("text", "done"),
        ]
    )
    out = agentcore_app.handle(
        {"mode": "describe", "first_day": B[0], "last_day": B[1]},
        a.s,
        model=model,
        session_factory=lambda: ts,
    )
    key = f"reports/describe/{B[0]}_{B[1]}/report.md"
    assert key in puts and b"Interpretation (written by the model" in puts[key]
    assert out["report"]["destination"].startswith("s3://rb/")


def test_scheduled_run_still_writes_the_report_when_the_model_fails(make_analysis, tmp_path, monkeypatch):
    import boto3

    puts = {}

    class S3Put:
        def put_object(self, Bucket, Key, Body, **kw):  # noqa: N803
            puts[Key] = Body

    monkeypatch.setattr(boto3, "client", lambda name, *a, **k: S3Put())
    a, est = make_analysis("full")
    a.s = a.s.with_overrides(report_bucket="rb")
    ts = ToolSession(a)
    model = ScriptedModel([("raise", "MaxTokensReachedException")])
    out = agentcore_app.handle(
        {"mode": "describe", "first_day": B[0], "last_day": B[1]},
        a.s,
        model=model,
        session_factory=lambda: ts,
    )
    assert out["agent_error"] == "RuntimeError" and out["fallback"]
    key = f"reports/describe/{B[0]}_{B[1]}/report.md"
    assert key in puts and b"Interpretation (written by the model" not in puts[key]
    gt = est.truth["by_window"]["B"]
    assert {r["path_class"]: r["bytes"] for r in ts.findings["path_volume"]["by_path"]["rows"]} == gt[
        "path_bytes"
    ]


def test_chat_answer_with_a_figure_no_tool_returned_is_flagged(make_analysis):
    """Seen in the eval: the model subtracted two returned figures in prose (a derived 294.0)."""
    a, _ = make_analysis("full")
    ts = ToolSession(a)
    model = ScriptedModel(
        [
            ("tool", "probe", {"first_day": B[0], "last_day": B[1]}),
            ("text", "The remainder is 294.0 after subtracting the two figures."),
        ]
    )
    out = agentcore_app.handle(
        {"mode": "chat", "prompt": "How much is left?", "first_day": B[0], "last_day": B[1]},
        a.s,
        model=model,
        session_factory=lambda: ts,
    )
    assert out["ungrounded_figures"] == ["294"]
    assert "294.0 after subtracting" in out["answer"] and "no tool returned" in out["answer"]


def test_chat_answer_repeating_tool_and_user_figures_is_not_flagged(make_analysis):
    a, _ = make_analysis("full")
    ts = ToolSession(a)
    model = ScriptedModel(
        [
            ("tool", "probe", {"first_day": B[0], "last_day": B[1]}),
            ("text", f"You asked about 777 flows. The window is {B[0]} to {B[1]} and the tier is {ts.probe(*B)['tier']['tier']}."),
        ]
    )
    out = agentcore_app.handle(
        {"mode": "chat", "prompt": "Explain 777 flows", "first_day": B[0], "last_day": B[1]},
        a.s,
        model=model,
        session_factory=lambda: ts,
    )
    assert out["ungrounded_figures"] == [] and "no tool returned" not in out["answer"]


def test_render_report_cannot_be_pointed_at_another_directory(make_analysis, tmp_path):
    """A model, or text a tool returned, must not be able to choose where the report is written."""
    import inspect

    assert "out_dir" not in inspect.signature(ToolSession.render_report).parameters
    a, _ = make_analysis("full")
    a.s = a.s.with_overrides(reports_dir=str(tmp_path / "reports"))
    ts = ToolSession(a)
    ts.describe(*B, compare_previous=False)
    with pytest.raises(TypeError):
        ts.render_report({}, out_dir=str(tmp_path / "elsewhere"))
    res = ts.render_report({})
    assert res["destination"].startswith(str(tmp_path / "reports")) and not (tmp_path / "elsewhere").exists()
