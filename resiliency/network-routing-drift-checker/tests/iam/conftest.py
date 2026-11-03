# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Synthesize the CDK template once per test session (no bundling, no AWS calls)."""

import json
import pathlib
import shutil
import subprocess  # nosec B404 -- runs cdk synth with a fixed argv, no shell, no untrusted input

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
INFRA = ROOT / "infra"
OUT = INFRA / "cdk.out.test"


@pytest.fixture(scope="session")
def template():
    npx = shutil.which("npx")
    if npx is None or not (INFRA / "node_modules").exists():
        pytest.fail("CDK toolchain missing: run `npm ci` in infra/ (the IAM lint must not be skipped)")
    # Fixed argument list, no shell, no user input: the npx path comes from shutil.which.
    subprocess.run([npx, "cdk", "synth", "--quiet", "-c", "skipBundling=true", "--output", str(OUT)],  # noqa: S603  # nosec B603 -- npx resolved via shutil.which, fixed argv, no shell
                   cwd=INFRA, check=True, capture_output=True, timeout=600)
    return json.loads((OUT / "NetworkRoutingDriftChecker.template.json").read_text())


@pytest.fixture(scope="session")
def link_template(template):
    """The cross-account companion stack (design.md D§3.3a). Synthesized with the checker."""
    return json.loads((OUT / "NetworkRoutingDriftChecker-DevOpsAgentLink.template.json").read_text())


@pytest.fixture(scope="session")
def allowlist():
    return json.loads((pathlib.Path(__file__).parent / "allowlist.json").read_text())
