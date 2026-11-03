# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Regression: a change to any file under src/ must change the Lambda asset hash.

Found live on 2026-10-13: a redeploy updated the state machine but not the Lambda code, because
the bundle's source fingerprint ignored src/ and CDK reused a stale cached bundle.
"""

import pathlib
import shutil
import subprocess  # nosec B404 -- runs ts-node with a fixed argv, no shell, no untrusted input

INFRA = pathlib.Path(__file__).resolve().parents[2] / "infra"
SCRIPT = "require('./lib/lambda-code').sourceHash()"


def _hash():
    npx = shutil.which("npx")
    out = subprocess.run([npx, "ts-node", "-e", f"process.stdout.write({SCRIPT})"],  # noqa: S603 - fixed args  # nosec B603 -- npx resolved via shutil.which, fixed argv, no shell
                         cwd=INFRA, check=True, capture_output=True, text=True, timeout=300)
    return out.stdout.strip()


def test_source_hash_changes_when_src_changes():
    probe = INFRA.parent / "src" / "drift_core" / "_hash_probe.py"
    before = _hash()
    try:
        probe.write_text("# temporary file for the asset-hash regression test\n")
        changed = _hash()
    finally:
        probe.unlink(missing_ok=True)
    after = _hash()
    assert len(before) == 64 and before != changed and before == after
