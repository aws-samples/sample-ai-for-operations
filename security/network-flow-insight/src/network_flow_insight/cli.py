# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""``nfi``: probe | report | chat | intent | drift | what-if | create-table | demo | mcp."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from datetime import date
from pathlib import Path
from typing import Any

from . import __version__
from .config import Settings, load_settings
from .core import s3layout
from .core.runbudget import RunBudgetExceeded
from .core.units import fmt_bytes
from .toolset import ToolSession


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nfi", description="Where does my data go? Evidence from VPC Flow Logs.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, window: bool = True) -> None:
        if window:
            sp.add_argument("--first", help="first day, YYYY-MM-DD (default: last N complete days)")
            sp.add_argument("--last", help="last day, YYYY-MM-DD")
            sp.add_argument("--days", type=int, help="window length when --first/--last are not given")
        sp.add_argument("--out", help="reports directory (default ./reports)")
        sp.add_argument(
            "--create-resources", action="store_true", help="allow creating the agent-managed Glue database"
        )
        sp.add_argument(
            "--yes",
            action="store_true",
            help="do not prompt when a query is above the cost ceiling (it is run)",
        )

    common(
        sub.add_parser(
            "probe", help="tier, inventory provider, coverage and scan estimate; no analysis query"
        )
    )
    r = sub.add_parser("report", help="describe the window and write the layered report")
    common(r)
    r.add_argument(
        "--no-model", action="store_true", help="deterministic report without model-written interpretation"
    )
    r.add_argument(
        "--no-compare", action="store_true", help="skip the previous-window comparison (saves one raw scan)"
    )
    r.add_argument(
        "--reference-bytes",
        type=int,
        help="a trusted NAT processed-bytes total for the window (reconciliation rung 4)",
    )
    sub_chat = sub.add_parser("chat", help="ask questions about the traffic")
    common(sub_chat)
    sub_chat.add_argument(
        "--remote", action="store_true", help="talk to the hosted AgentCore Runtime instead"
    )
    i = sub.add_parser("intent", help="draft a baseline intent file from the window")
    common(i)
    i.add_argument("--write", help="write the draft here instead of stdout")
    for name in ("drift", "what-if"):
        common(sub.add_parser(name, help=f"{name} against the committed intent file"))
    ct = sub.add_parser(
        "create-table",
        help="opt-in: create a projection table, database and workgroup over the flow-log bucket",
    )
    ct.add_argument("--confirm", action="store_true", help="actually create (otherwise only show the plan)")
    ct.add_argument("--first", help="first day to project from, YYYY-MM-DD")
    d = sub.add_parser("demo", help="full report from a bundled synthetic estate; no AWS access")
    d.add_argument("--tier", choices=("basic", "enhanced", "full"), default="full")
    d.add_argument(
        "--no-inventory", action="store_true", help="run at provider D (inferred) to see the lower tier"
    )
    d.add_argument("--out", help="reports directory (default ./reports)")
    ge = sub.add_parser(
        "demo-estate",
        help="write the synthetic estate to a directory (flow logs in AWSLogs/ layout) for upload to S3",
    )
    ge.add_argument("dir")
    ge.add_argument("--tier", choices=("basic", "enhanced", "full"), default="full")
    m = sub.add_parser("mcp", help="serve the tools over stdio MCP (no model)")
    common(m)
    m.add_argument("--demo", action="store_true", help="serve the synthetic estate instead of AWS")
    return p


def _settings(args: argparse.Namespace) -> Settings:
    s = load_settings()
    return s.with_overrides(reports_dir=getattr(args, "out", None))


def _window(args: argparse.Namespace, s: Settings) -> tuple[str, str]:
    if getattr(args, "first", None) and getattr(args, "last", None):
        date.fromisoformat(args.first)
        date.fromisoformat(args.last)
        return args.first, args.last
    n = getattr(args, "days", None) or s.default_window_days
    return s3layout.previous_complete_days(date.today(), n)


def _confirm_factory(assume_yes: bool):
    def confirm(label: str, est: dict) -> bool:
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            return False
        ans = input(f"'{label}' is estimated at {est['gb']} GB (about USD {est['cost_usd']}). Run it? [y/N] ")
        return ans.strip().lower() in ("y", "yes")

    return confirm


def _aws_session(
    args: argparse.Namespace, s: Settings, first: str, last: str, reference: dict | None = None
) -> ToolSession:
    from . import aws_backend

    a = aws_backend.build_analysis(
        s,
        first,
        last,
        interactive=True,
        confirm=_confirm_factory(getattr(args, "yes", False)),
        reference=reference,
        create_agent_resources=getattr(args, "create_resources", False),
    )
    return ToolSession(a)


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import estate as E
    from .demo.runner import build_analysis

    s = load_settings().with_overrides(reports_dir=args.out, aws_region=E.REGION)
    with tempfile.TemporaryDirectory(prefix="nfi-demo-") as tmp:
        a, est = build_analysis(Path(tmp) / "estate", args.tier, s, inventory=not args.no_inventory)
        ts = ToolSession(a)
        res = ts.describe(*E.WINDOW_B)
        out = ts.render_report()
    print(f"Synthetic estate, tier {res['tier']}, inventory provider {res['inventory_provider']}")
    for h in res["headlines"]:
        print(f"  - {h}")
    print(f"Reconciliation: {res['reconciliation']['verdict']}")
    print(f"Report written to {out['destination']}")
    return 0


def cmd_demo_estate(args: argparse.Namespace) -> int:
    from .demo.generator import generate

    est = generate(args.dir, args.tier)
    print(f"Wrote the {args.tier} estate to {est.root}.")
    print(
        f"Upload the flow logs with: aws s3 sync {est.s3_root}/ s3://<your-test-bucket>/ (the AWSLogs/ prefix is inside)"
    )
    print(f"Inventory file: {est.inventory_path}; ground truth: {est.truth_path}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    s = _settings(args)
    first, last = _window(args, s)
    ts = _aws_session(args, s, first, last)
    _print_json(ts.probe(first, last))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    s = _settings(args)
    first, last = _window(args, s)
    ref = (
        {"category": "nat_processing", "bytes": args.reference_bytes, "scope": "operator supplied"}
        if args.reference_bytes
        else None
    )
    ts = _aws_session(args, s, first, last, ref)
    print(f"Window {first} to {last}. Estimated scan: {ts.estimate_scan(first, last)}")
    if args.no_model:
        res = ts.describe(first, last, compare_previous=not args.no_compare)
        if res.get("status") != "ok":
            print(res)
            return 2
        out = ts.render_report()
    else:
        from . import agent as agent_mod

        agent = agent_mod.create_agent(ts, s)
        agent(agent_mod.DESCRIBE_PROMPT.format(window=f"{first} to {last}"))
        if ts.findings is None:
            print("The agent did not complete the analysis.")
            return 2
        out = {"destination": str(Path(s.reports_dir) / f"{first}_{last}")}
    print(f"Report: {out['destination']}/report.md")
    print(
        f"Scanned {fmt_bytes(ts.a.b.engine.gauge.total_bytes)}; estimated cost USD {ts.a.b.engine.gauge.total_cost_usd}"
    )
    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    s = _settings(args)
    if args.remote:
        return _chat_remote(s)
    first, last = _window(args, s)
    ts = _aws_session(args, s, first, last)
    from . import agent as agent_mod

    agent = agent_mod.create_agent(ts, s)
    print("Ask about the traffic. Empty line to quit.")
    while True:
        try:
            q = input("> ").strip()
        except EOFError:
            break
        if not q:
            break
        try:
            answer = str(agent_mod.ask(agent, q))
        except RunBudgetExceeded:
            # after a hard stop the agent's history may end mid tool call, so the session ends instead of limping on
            print("The run budget (NFI_MAX_TOOL_CALLS, NFI_RUN_DEADLINE_SECONDS) was used up. Start a new chat.")
            return 1
        figures = agent_mod.answer_figures_not_from_tools(agent, q, answer)
        if figures:
            print(agent_mod.with_figure_caution("", figures).strip())
        print()
    return 0


def _chat_remote(s: Settings) -> int:  # pragma: no cover - needs a deployed runtime
    import boto3

    if not s.agentcore_runtime_arn:
        print("Set NFI_AGENTCORE_RUNTIME_ARN to the hosted runtime's ARN.")
        return 2
    client = boto3.client("bedrock-agentcore", region_name=s.aws_region)
    import uuid

    sid = uuid.uuid4().hex + uuid.uuid4().hex
    print("Ask about the traffic. Empty line to quit.")
    while True:
        q = input("> ").strip()
        if not q:
            return 0
        r = client.invoke_agent_runtime(
            agentRuntimeArn=s.agentcore_runtime_arn,
            runtimeSessionId=sid,
            payload=json.dumps({"mode": "chat", "prompt": q}).encode(),
        )
        print(r["response"].read().decode())


def cmd_intent(args: argparse.Namespace) -> int:
    s = _settings(args)
    first, last = _window(args, s)
    ts = _aws_session(args, s, first, last)
    res = ts.intent_draft(first, last)
    if args.write:
        Path(args.write).write_text(res["yaml"])
        print(f"{res['entries']} entries written to {args.write}. Prune it, commit it, set NFI_INTENT_FILE.")
    else:
        print(res["yaml"])
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    s = _settings(args)
    first, last = _window(args, s)
    ts = _aws_session(args, s, first, last)
    _print_json(ts.drift(first, last) if args.cmd == "drift" else ts.what_if(first, last))
    return 0


def cmd_create_table(args: argparse.Namespace) -> int:  # pragma: no cover - needs AWS
    from . import aws_backend
    from .tools import create_table

    s = load_settings()
    if not s.flow_log_bucket:
        print("Set NFI_FLOW_LOG_BUCKET.")
        return 2
    sess = aws_backend.make_session(s)
    first = args.first or ""
    inv = s3layout.discover(sess.client("s3"), s.flow_log_bucket, s.flow_log_prefix)
    first_scan = inv.days[0] if inv.days else ""
    res = create_table.create_table(
        glue=sess.client("glue"),
        athena=sess.client("athena"),
        s3=sess.client("s3"),
        log_inventory=inv,
        first_day=first or first_scan,
        agent_database=s.agent_database,
        table=s.flow_log_table or "nfi_flow_logs",
        workgroup=s.athena_workgroup if s.athena_workgroup != "primary" else "nfi-agent",
        results_location=s.athena_results_location or f"s3://{s.report_bucket}/athena-results/",
        confirmed=args.confirm,
    )
    _print_json({k: v for k, v in res.items() if k != "plan"} | {"plan": res["plan"]})
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:  # pragma: no cover - blocks on stdio
    from . import mcp_server

    if args.demo:
        from .demo import estate as E
        from .demo.runner import build_analysis

        a, _ = build_analysis(tempfile.mkdtemp(prefix="nfi-demo-"), "full")
        ts = ToolSession(a)
        ts.findings_window = E.WINDOW_B
    else:
        s = _settings(args)
        first, last = _window(args, s)
        ts = _aws_session(args, s, first, last)
        ts.findings_window = (first, last)
    mcp_server.serve(ts)
    return 0


COMMANDS = {
    "demo": cmd_demo,
    "demo-estate": cmd_demo_estate,
    "probe": cmd_probe,
    "report": cmd_report,
    "chat": cmd_chat,
    "intent": cmd_intent,
    "drift": cmd_drift,
    "what-if": cmd_drift,
    "create-table": cmd_create_table,
    "mcp": cmd_mcp,
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=load_settings().log_level, stream=sys.stderr, format="%(message)s")
    try:
        return COMMANDS[args.cmd](args)
    except Exception as exc:
        from .aws_backend import SetupNeeded

        if isinstance(exc, SetupNeeded):
            print(f"Setup needed: {exc}", file=sys.stderr)
            if exc.plan:
                print(json.dumps(exc.plan, indent=2, default=str), file=sys.stderr)
            return 3
        raise


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
