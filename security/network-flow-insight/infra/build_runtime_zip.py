#!/usr/bin/env python3
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Build the direct-code deployment package for Amazon Bedrock AgentCore Runtime (arm64, Python 3.12).

An alternative to the container image when no container engine is available:

    python infra/build_runtime_zip.py            # writes infra/dist/runtime.zip
    cd infra && npx cdk deploy -c artifact=code ...

Dependencies are resolved for linux/arm64 wheels, so it can be built on any machine with pip.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = Path(__file__).resolve().parent / "dist"
ENTRY = """# Entry point for AgentCore Runtime direct code deployment.
from network_flow_insight.agentcore_app import build_app

app = build_app()

if __name__ == "__main__":
    app.run()
"""
PLATFORMS = ("manylinux2014_aarch64", "manylinux_2_28_aarch64", "manylinux_2_17_aarch64")


def main() -> int:
    work = DIST / "pkg"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--quiet",
        "--target",
        str(work),
        "--implementation",
        "cp",
        "--python-version",
        "3.12",
        "--only-binary=:all:",
        "-r",
        str(ROOT / "requirements.txt"),
    ]
    for p in PLATFORMS:
        cmd += ["--platform", p]
    subprocess.run(cmd, check=True)  # noqa: S603  # fixed argument list built from constants, no shell and no user input  # nosemgrep: dangerous-subprocess-use-audit
    shutil.copytree(
        ROOT / "src" / "network_flow_insight",
        work / "network_flow_insight",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (work / "main.py").write_text(ENTRY)
    out = DIST / "runtime.zip"
    out.unlink(missing_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for f in sorted(work.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts and not f.name.endswith(".pyc"):
                z.write(f, f.relative_to(work))
    shutil.rmtree(work)
    print(f"wrote {out} ({out.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
