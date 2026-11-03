# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Documentation examples stay valid (tasks.md 2.7): the shipped example file and every
intent example in the README must pass the validator, and the README's error example must
match what the validator actually prints."""

import pathlib
import re

from drift_core.intent import parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text()


def test_example_file_is_valid():
    result = parse((ROOT / "examples" / "routing-intent.example.yaml").read_text())
    assert result.status == "ok", result.errors
    model = result.document
    assert model["tgw_isolation"] and model["dx_redundancy_pairs"] and model["hybrid_paths"]


def test_readme_yaml_examples_are_valid():
    blocks = re.findall(r"```yaml\n(.*?)```", README, re.S)
    assert blocks, "README must contain at least one yaml example"
    for block in blocks:
        assert parse(block).status == "ok", (block, parse(block).errors)


def test_readme_rejection_example_matches_validator():
    bad = "version: 1\ndx_redundency_pairs: []\ndx_redundancy_pairs:\n  - name: a\n    members: [dxvif-01]\n"
    errors = parse(bad).errors
    for line in errors:
        assert line in README, f"README rejection example is out of date: {line}"
