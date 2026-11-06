# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""A tiny S3 look-alike over a local directory: just the calls the layout walker makes."""

from __future__ import annotations

import io
from pathlib import Path


class LocalS3:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def list_objects_v2(
        self, Bucket: str, Prefix: str = "", Delimiter: str = "", ContinuationToken: str = ""
    ) -> dict:  # noqa: N803
        base = self.root
        keys = sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
        keys = [k for k in keys if k.startswith(Prefix)]
        if not Delimiter:
            return {
                "Contents": [{"Key": k, "Size": (base / k).stat().st_size} for k in keys],
                "IsTruncated": False,
            }
        prefixes: set[str] = set()
        contents = []
        for k in keys:
            rest = k[len(Prefix) :]
            if Delimiter in rest:
                prefixes.add(Prefix + rest.split(Delimiter, 1)[0] + Delimiter)
            else:
                contents.append({"Key": k, "Size": (base / k).stat().st_size})
        return {
            "CommonPrefixes": [{"Prefix": p} for p in sorted(prefixes)],
            "Contents": contents,
            "IsTruncated": False,
        }

    def get_object(self, Bucket: str, Key: str, Range: str = "") -> dict:  # noqa: N803
        data = (self.root / Key).read_bytes()
        if Range.startswith("bytes="):
            lo, hi = Range[6:].split("-")
            data = data[int(lo) : int(hi) + 1]
        return {"Body": io.BytesIO(data)}

    def head_object(self, Bucket: str, Key: str) -> dict:  # noqa: N803
        return {"ContentLength": (self.root / Key).stat().st_size}
