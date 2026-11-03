# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Finding model and deterministic finding IDs (design.md D§5).

Precision code: no I/O, no clock, no randomness. The same drift must yield a
byte-identical finding_id on every run, independent of field order, list order,
timestamps or observed counts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("drift", "informational", "system")
CHECKS = ("check1", "check2", "check3", "check4", "check5", "check6", "informational", "system")


def canonical_prefix(prefix: str) -> str:
    """Normalize a CIDR (e.g. '10.0.1.5/16' -> '10.0.0.0/16', IPv6 compressed lower-case).

    Non-CIDR values (prefix-list IDs) are lower-cased and returned unchanged.
    """
    text = prefix.strip()
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text.lower()


def canonical_json(value: Any) -> str:
    """Stable JSON: sorted keys, sorted lists of scalars, no whitespace."""

    def normalize(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {str(k): normalize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set, frozenset)):
            items = [normalize(v) for v in obj]
            try:
                return sorted(items, key=lambda x: json.dumps(x, sort_keys=True))
            except TypeError:
                return items
        return obj

    return json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), default=str)


def finding_id(kind: str, region: str, identity: tuple[str, ...] | list[str]) -> str:
    """Deterministic ID: 'f-' + first 20 hex chars of sha256('kind|region|sorted identity')."""
    parts = sorted(str(p).strip().lower() for p in identity)
    material = "|".join([kind.strip().lower(), region.strip().lower(), *parts])
    return "f-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


@dataclass(frozen=True)
class Finding:
    """One unit of drift (or an informational / system note) — D§5."""

    check: str
    kind: str
    severity: str
    region: str
    identity: tuple[str, ...]
    expected: dict[str, Any] = field(default_factory=dict)
    observed: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    message: str = ""

    def __post_init__(self) -> None:
        if self.check not in CHECKS:
            raise ValueError(f"unknown check {self.check!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")
        if not self.kind:
            raise ValueError("kind is required")
        if not self.identity:
            raise ValueError("identity must contain at least one stable identifier")
        object.__setattr__(self, "identity", tuple(sorted(str(p).strip().lower() for p in self.identity)))

    @property
    def finding_id(self) -> str:
        return finding_id(self.kind, self.region, self.identity)

    @property
    def payload_hash(self) -> str:
        """Change detection for KNOWN findings; excludes nothing that defines *what* drifted."""
        material = canonical_json({"expected": self.expected, "observed": self.observed})
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "check": self.check,
            "kind": self.kind,
            "severity": self.severity,
            "region": self.region,
            "identity": list(self.identity),
            "expected": self.expected,
            "observed": self.observed,
            "context": self.context,
            "message": self.message,
            "payload_hash": self.payload_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            check=data["check"],
            kind=data["kind"],
            severity=data["severity"],
            region=data["region"],
            identity=tuple(data["identity"]),
            expected=data.get("expected", {}),
            observed=data.get("observed", {}),
            context=data.get("context", {}),
            message=data.get("message", ""),
        )


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop exact duplicates by finding_id (first wins) and return a stable order."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.finding_id, f)
    return sorted(seen.values(), key=lambda f: (f.check, f.kind, f.region, f.identity))
