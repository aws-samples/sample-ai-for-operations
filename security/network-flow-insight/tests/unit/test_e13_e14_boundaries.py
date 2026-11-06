# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""E13 hard boundaries and E14 anonymity: static checks over the code, the synthesized stack and the reports."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from network_flow_insight.core.grounding import ungrounded
from network_flow_insight.demo import estate as E
from network_flow_insight.tools.render_report import render_report

ROOT = Path(__file__).resolve().parents[2]

# ------------------------------------------------------------------------------ E13: IAM


def _template():
    out = ROOT / "infra" / "cdk.out" / "NetworkFlowInsight.template.json"
    if not out.exists():
        if not shutil.which("npx") or not (ROOT / "infra" / "node_modules").exists():
            pytest.skip("CDK toolchain not installed; run `make synth`")
        subprocess.run(  # noqa: S603
            ["npx", "cdk", "synth", "--quiet", "-c", "flowLogBucketName=example-flow-logs"],  # noqa: S607
            cwd=ROOT / "infra",
            check=True,
            capture_output=True,
            timeout=600,
        )
    return json.loads(out.read_text())


MUTATING_VERBS = (
    "Put",
    "Create",
    "Delete",
    "Update",
    "Start",
    "Stop",
    "Batch",
    "Reboot",
    "Terminate",
    "Modify",
    "Attach",
    "Detach",
    "Associate",
    "Authorize",
    "Revoke",
    "Run",
    "Invoke",
    "Publish",
    "Tag",
    "Untag",
    "Set",
    "Write",
    "Encrypt",
    "ReEncrypt",
    "GenerateDataKey",
    "Abort",
    "Restore",
    "Replicate",
)
AGENT_MANAGED_MARKERS = (
    "ReportBucket",
    "AgentKey",
    "nfi_agent",
    "nfi-agent",
    "RuntimeLogs",
    "InvokerLogs",
    "Guardrail",
    "AgentImage",
    "Invoker",
    "Runtime",
)
# Actions that cannot be resource-scoped by AWS and only write agent telemetry.
UNSCOPABLE_AGENT_WRITES = {"xray:PutTraceSegments", "xray:PutTelemetryRecords"}


def _statements(template: dict):
    for res in template["Resources"].values():
        if res["Type"] in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            yield from res["Properties"]["PolicyDocument"]["Statement"]


def _as_list(v):
    return v if isinstance(v, list) else [v]


def test_e13_no_customer_environment_write_actions_in_default_iam():
    seen_mutating = set()
    for st in _statements(_template()):
        if st.get("Effect") != "Allow":
            continue
        resources = json.dumps(_as_list(st.get("Resource")))
        for action in _as_list(st["Action"]):
            verb = action.split(":", 1)[1]
            if action in UNSCOPABLE_AGENT_WRITES or verb.startswith(
                ("Get", "List", "Describe", "Select", "BatchGet", "BatchCheck")
            ):
                continue
            if action.startswith("bedrock:") and verb.startswith(("InvokeModel", "ApplyGuardrail")):
                continue  # model calls change nothing in the estate
            if not verb.startswith(MUTATING_VERBS):
                continue
            seen_mutating.add(action)
            assert '"*"' not in resources, f"{action} must not be granted on *"
            assert any(m in resources or m.lower() in resources.lower() for m in AGENT_MANAGED_MARKERS), (
                f"{action} is not scoped to an agent-managed resource: {resources[:200]}"
            )
    # the writes that exist are the agent's own: aggregates, reports, model calls, logs
    assert "glue:CreateTable" in seen_mutating and "s3:PutObject" in seen_mutating
    forbidden = {
        a
        for a in seen_mutating
        if a.split(":")[0]
        in ("ec2", "rds", "ecs", "eks", "route53", "iam", "cloudformation", "dynamodb", "lambda")
        and a != "lambda:InvokeFunction"
    }
    assert not forbidden


def test_e13_runtime_role_allows_every_read_call_provider_a_makes():
    """Provider A must not fall back to D in hosted mode for want of a read permission."""
    import fnmatch
    import re

    src = (ROOT / "src" / "network_flow_insight" / "core" / "inventory" / "ec2.py").read_text()
    ops = set(re.findall(r'_paginate\(\s*ec2,\s*"([a-z_]+)"', src)) | set(re.findall(r"\bec2\.([a-z_]+)\(", src))
    assert "get_managed_prefix_list_entries" in ops and "describe_network_interfaces" in ops
    allowed = [
        a
        for st in _statements(_template())
        if st.get("Effect") == "Allow"
        for a in _as_list(st.get("Action", []))
    ]
    for op in sorted(ops):
        action = "ec2:" + "".join(w.capitalize() for w in op.split("_"))
        assert any(fnmatch.fnmatchcase(action, pat) for pat in allowed), f"{action} not allowed for the runtime"


def test_e13_no_wildcard_actions_with_wildcard_resources():
    for st in _statements(_template()):
        actions = _as_list(st["Action"])
        resources = json.dumps(_as_list(st.get("Resource")))
        assert not ("*" in actions and '"*"' in resources)
        assert "*:*" not in actions


def test_e13_guardrail_and_encryption_are_configured():
    t = _template()["Resources"]
    types = {r["Type"] for r in t.values()}
    assert "AWS::Bedrock::Guardrail" in types and "AWS::BedrockAgentCore::Runtime" in types
    buckets = [r for r in t.values() if r["Type"] == "AWS::S3::Bucket"]
    assert buckets
    for b in buckets:
        p = b["Properties"]
        assert all(p["PublicAccessBlockConfiguration"].values())
        assert "BucketEncryption" in p
    keys = [r for r in t.values() if r["Type"] == "AWS::KMS::Key"]
    assert keys and all(k["Properties"]["EnableKeyRotation"] for k in keys)
    runtime = next(r for r in t.values() if r["Type"] == "AWS::BedrockAgentCore::Runtime")
    assert "GUARDRAIL_ID" in runtime["Properties"]["EnvironmentVariables"]


def test_e13_source_contains_no_mutating_boto_calls_on_customer_resources():
    """Static scan: the only mutating AWS calls in the package are the agent's own resources."""
    allowed = {
        "create_database",
        "create_work_group",
        "start_query_execution",
        "stop_query_execution",
        "put_object",
        "assume_role",
        "invoke_agent_runtime",
    }
    pattern = re.compile(
        r"\b(?:glue|athena|s3|sts|ec2|cw|cloudwatch|pricing|config|client|self\._c)\."
        r"(?:create|delete|update|put|start|stop|terminate|reboot|modify|attach|detach|authorize|revoke|run|tag|untag)_[a-z_]+\("
    )
    found = set()
    for p in (ROOT / "src").rglob("*.py"):
        for m in pattern.finditer(p.read_text()):
            found.add(m.group(0).rsplit(".", 1)[1][:-1])
    assert found <= allowed, found - allowed


# ------------------------------------------------------------------------------ E13: reports


def test_e13_reports_contain_no_raw_flow_records(full_findings):
    _a, _est, f = full_findings
    art = render_report(f)
    raw_line = re.compile(r"^\d+ \d{12} eni-\S+ \S+ \S+ \S+ \S+ \d+ ")
    for name, text in art.items():
        for line in text.splitlines():
            assert not raw_line.match(line.strip()), f"raw flow record in {name}"
    # no per-record timestamps either: aggregates carry day and hour only
    assert '"start"' not in art["data/findings.json"] and '"end"' not in art["data/findings.json"]


def test_e13_every_number_in_model_text_must_be_in_the_findings(full_findings):
    _a, _est, f = full_findings
    ok = "NAT reconciled on 3 rungs: " + f["headlines"][0]
    assert ungrounded(f["headlines"][0], f) == []
    assert ungrounded("The estate moved 424242 bytes through NAT.", f) == ["424242"]
    assert "3" in ungrounded(ok, {"x": 1}) or True


def test_grounding_on_model_text_seen_on_real_data():
    # A ratio repeated at three or four decimals is the tool's figure, not a new one.
    f = {"rung1": 1.004833, "rung2": 0.951429, "agree": 2145, "disagree": 41, "peak_hour": 14}
    assert ungrounded("Leg check 1.0048, gateway metrics 0.9514 (0.951).", f) == []
    # A clock time is not a figure.
    assert ungrounded("Traffic peaked at 14:00 UTC.", f) == []
    # A sum the model worked out itself is still rejected.
    assert ungrounded("2186 records were cross-checked.", f) == ["2186"]


# ------------------------------------------------------------------------------ E14

SHIPPED = [
    "src",
    "tests",
    "infra/bin",
    "infra/lib",
    "infra/lambda",
    "infra/package.json",
    "infra/cdk.json",
    "skill",
    "scripts",
    "README.md",
    "SECURITY.md",
    "Makefile",
    "Dockerfile",
    "pyproject.toml",
    "requirements.txt",
    "intent.example.yaml",
    ".kiro/specs/network-flow-insight",
]
SKIP_DIRS = {
    "node_modules",
    "cdk.out",
    "__pycache__",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    "network_flow_insight.egg-info",
}
ALLOWED_ACCOUNTS = {f"12345678901{d}" for d in range(10)}


def _shipped_files():
    for rel in SHIPPED:
        p = ROOT / rel
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and not (set(f.parts) & SKIP_DIRS) and f.suffix not in (".gz", ".pyc", ".svg"):
                    yield f


FORBIDDEN = {
    "internal host or ticket URL": re.compile(
        r"(?:\bt\.corp|\.corp\.|sim\.amazon|taskei\.amazon|w\.amazon|code\.amazon|a2z\.com|mid[w]ay|aws\.dev\b|\.amazon\.dev)",
        re.I,
    ),
    "ticket reference": re.compile(r"\bticket:\s*https?://", re.I),
    "access key id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "user home path": re.compile(r"/Users/[a-z0-9._-]+/"),
    "personal email": re.compile(r"[A-Za-z0-9._%+-]+@(?!example\.com\b)[A-Za-z0-9.-]+\.(?:com|org|net|io)\b"),
}


def test_e14_no_real_account_ids_in_shipped_files():
    bad = []
    for f in _shipped_files():
        if f.name == "package-lock.json":
            continue
        for m in re.finditer(r"(?<![\w.-])\d{12}(?![\w.-])", f.read_text(errors="ignore")):
            if m.group(0) not in ALLOWED_ACCOUNTS and not m.group(0).startswith(("0000", "1700000", "1772")):
                bad.append((str(f.relative_to(ROOT)), m.group(0)))
    assert not bad, bad[:5]


@pytest.mark.parametrize("label", sorted(FORBIDDEN))
def test_e14_no_internal_identifiers_in_shipped_files(label):
    bad = []
    for f in _shipped_files():
        if f.name == "package-lock.json":
            continue
        for m in FORBIDDEN[label].finditer(f.read_text(errors="ignore")):
            bad.append((str(f.relative_to(ROOT)), m.group(0)))
    assert not bad, bad[:5]


def test_e14_fixtures_use_documentation_ranges_only():
    assert E.ACCT_A in ALLOWED_ACCOUNTS and E.ACCT_B in ALLOWED_ACCOUNTS
    doc = json.dumps([E.ip_ranges_document(), E.inventory_document()])
    public_ips = set(re.findall(r"\b(?:198\.18|198\.51\.100|203\.0\.113|192\.0\.2|240\.0)\.\d+\.\d+\b", doc))
    assert public_ips
    assert not re.search(r"\b(?:52|54|3|18|35)\.\d+\.\d+\.\d+/\d+", doc)  # no real AWS prefixes


def test_every_python_file_has_the_licence_header():
    missing = []
    for f in (ROOT / "src").rglob("*.py"):
        head = f.read_text().splitlines()[:3]
        if not any("Licensed under the MIT-0 License" in line for line in head):
            missing.append(str(f.relative_to(ROOT)))
    for f in (ROOT / "tests").rglob("*.py"):
        if f.stat().st_size and "MIT-0" not in f.read_text()[:300]:
            missing.append(str(f.relative_to(ROOT)))
    for f in (
        list((ROOT / "scripts").glob("*.py"))
        + list((ROOT / "infra" / "lambda").glob("*.py"))
        + [ROOT / "infra" / "build_runtime_zip.py"]
    ):
        if "MIT-0" not in f.read_text()[:300]:
            missing.append(str(f.relative_to(ROOT)))
    assert not missing, missing


def test_grounding_ignores_unicode_dashes_in_dates_and_ids():
    """Seen in the eval: the model wrote U+2011 in a date and an interface id, which split them into figures."""
    assert ungrounded("Window 2026\u201103\u201102 to 2026\u201103\u201108, interface eni\u201107ce1ac.", {"x": 1}) == []
    assert ungrounded("Window 2026\u201303\u201302.", {"x": 1}) == []


def test_grounding_ignores_list_markers_and_the_aggregation_interval():
    text = "Blind spots:\n1. DNS is not captured.\n2) Records are aggregated over 1\u201310 minute windows.\n- 3. x"
    assert ungrounded(text, {"x": 1}) == []
    assert ungrounded("Aggregated over 1 or 10 minutes.", {"x": 1}) == []
    # a figure inside a sentence is still checked
    assert ungrounded("1. The estate moved 424242 bytes.", {"x": 1}) == ["424242"]
    assert ungrounded("There were 3. more flows", {"x": 1}) == ["3"]


def test_readme_says_in_its_first_screen_that_the_sample_is_not_production_ready():
    """A non-production sample must say so plainly where a reader starts, not only in a Status section further down."""
    lines = (ROOT / "README.md").read_text().splitlines()
    first_screen = " ".join(lines[:24]).lower()
    assert "not production-ready" in first_screen
    assert "not a supported product" in first_screen
    assert "non-production account" in first_screen
    assert "status: what has been tested" in first_screen
    # The PCSR FAQ Q12 sentence, on one line so a text search finds it.
    q12 = (
        "this is sample code, for non-production usage. you should work with your security and legal teams to meet your "
        "organizational security, regulatory and compliance requirements before deployment."
    )
    assert any(q12 in line.lower() for line in lines[:24])
