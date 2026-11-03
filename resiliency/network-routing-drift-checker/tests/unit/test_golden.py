# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Golden output for the evaluate step over the REAL lab recording (tasks.md 1.22).

Any change to a check, the finding model or the IDs shows up here as a diff. If the change is
intended, regenerate with:  UPDATE_GOLDEN=1 .venv/bin/pytest tests/unit/test_golden.py
and review the diff of tests/fixtures/recorded/golden_findings.json before committing.
"""

import json
import os
import pathlib

from drift_core.collectors import cloudwan, directconnect, tgw
from drift_core.evaluate import evaluate

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "recorded"
GOLDEN = FIXTURES / "golden_findings.json"
MANIFEST = {"tag_key": "Environment", "limit_threshold_percent": 80.0, "limit_threshold_overrides": {},
            "intent": {"status": "absent", "errors": []}, "dx_gateways": {"status": "ok"}}


def _evaluate():
    raw = json.loads((FIXTURES / "raw_responses.json").read_text())
    regions = {name: {"region": name, **tgw.normalize_region(data["tgw"]),
                      **directconnect.normalize_region(name, data["dx"], raw["dx_gateways"])}
               for name, data in raw["regions"].items()}
    return evaluate(cloudwan.normalize(raw["cloudwan"]), regions, MANIFEST, {}).to_dict()


def test_evaluate_matches_golden():
    actual = json.loads(json.dumps(_evaluate(), sort_keys=True))
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
    expected = json.loads(GOLDEN.read_text())
    assert actual == expected, "evaluate output changed; see the module docstring to regenerate"


def test_golden_content_sanity():
    golden = json.loads(GOLDEN.read_text())
    kinds = sorted(f["kind"] for f in golden["findings"])
    assert kinds == ["blackhole-route"] * 6 + ["untagged-route-table"]
    assert golden["checks_run"] == ["check1", "check2", "check3", "check5"]
    assert golden["regions_evaluated"] == ["eu-central-1", "eu-west-1", "us-east-1"]
    assert golden["skip_reason"] == "intent file absent"
