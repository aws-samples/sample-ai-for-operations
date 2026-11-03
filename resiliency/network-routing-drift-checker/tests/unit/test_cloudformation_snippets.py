# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Customer-deployed CloudFormation snippets (tasks.md 3.8): lint-clean and read-only."""

import pathlib
import re
import shutil
import subprocess  # nosec B404 -- runs cfn-lint with a fixed argv, no shell, no untrusted input

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SNIPPET = ROOT / "cloudformation" / "devops-agent-network-reads.yaml"
TEXT = SNIPPET.read_text(encoding="utf-8")


def test_snippet_is_cfn_lint_clean():
    cfn_lint = shutil.which("cfn-lint", path=str(ROOT / ".venv" / "bin")) or shutil.which("cfn-lint")
    if cfn_lint is None:
        pytest.fail("cfn-lint missing: install requirements-dev.txt (the lint must not be skipped)")
    result = subprocess.run([cfn_lint, str(SNIPPET)], capture_output=True, text=True, timeout=120)  # noqa: S603  # nosec B603 -- fixed argv, cfn_lint resolved via shutil.which, no shell
    assert result.returncode == 0, result.stdout + result.stderr


def test_snippet_grants_only_the_two_documented_reads_scoped_by_arn():
    actions = re.findall(r"Action:\s*(\S+)", TEXT)
    assert sorted(actions) == ["networkmanager:GetCoreNetworkChangeEvents", "networkmanager:GetNetworkRoutes"]
    assert "Resource: \"*\"" not in TEXT and "Resource: '*'" not in TEXT
    assert ":global-network/*" in TEXT and ":core-network/*" in TEXT


def test_readme_points_to_the_snippet():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "cloudformation/devops-agent-network-reads.yaml" in readme
