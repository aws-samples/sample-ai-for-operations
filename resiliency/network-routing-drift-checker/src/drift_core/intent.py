# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Hybrid intent file: schema validation with line numbers (requirements §7, tasks.md 2.1).

Precision code. Two stages:
- `parse(text)`: YAML + schema. Runs in `init`. Any error -> status "rejected" with
  "line N: ..." messages; Phase 1 checks still run, intent-dependent checks are skipped.
- `resolve_isolation(model, regions, tag_key)`: semantic check of `tgw_isolation` names
  against the collected route tables. Runs in `evaluate` (needs snapshots).

The file is never written by the solution (requirements §7.3, §13 item 1).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

SCHEMA_VERSION = 1
TOP_KEYS = ("version", "tgw_isolation", "dx_redundancy_pairs", "hybrid_paths", "regions")
PAIR_KEYS = ("name", "members")
PATH_KEYS = ("prefix", "exit_region", "preferred", "backup")
REGION_KEYS = ("allow", "exclude")
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
VIF_RE = re.compile(r"^dxvif-[0-9a-z]+$")
ATTACHMENT_RE = re.compile(r"^(dxvif|tgw-attach|attachment|vpn|dxgw)-[0-9a-z]+$"
                           r"|^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")  # last form: DX gateway ID


@dataclass(frozen=True)
class IntentLoad:
    status: str  # "absent" | "ok" | "rejected" | "unreadable"
    document: dict[str, Any] | None = None  # the validated model (see _empty_model)
    version_id: str | None = None
    errors: list[str] = field(default_factory=list)

    def manifest_entry(self) -> dict[str, Any]:
        return {"status": self.status, "version_id": self.version_id, "errors": list(self.errors),
                "model": self.document}


def _empty_model() -> dict[str, Any]:
    return {"version": SCHEMA_VERSION, "tgw_isolation": {}, "dx_redundancy_pairs": [], "hybrid_paths": [],
            "regions": {"allow": [], "exclude": []}, "lines": {}}


class _Errors:
    def __init__(self) -> None:
        self.items: list[tuple[int, str]] = []

    def add(self, node: yaml.Node | None, message: str) -> None:
        line = node.start_mark.line + 1 if node is not None else 1
        self.items.append((line, f"line {line}: {message}"))

    def sorted(self) -> list[str]:
        return [text for _, text in sorted(self.items)]


def _scalar(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    return loader.construct_object(node, deep=True)


def _mapping(loader: yaml.SafeLoader, node: yaml.Node, what: str, allowed: tuple[str, ...],
             errors: _Errors) -> dict[str, tuple[yaml.Node, yaml.Node]] | None:
    """Mapping node -> {key: (key_node, value_node)}; reports wrong type, duplicate and unknown keys."""
    if not isinstance(node, yaml.MappingNode):
        errors.add(node, f"{what} must be a mapping (key: value)")
        return None
    out: dict[str, tuple[yaml.Node, yaml.Node]] = {}
    for key_node, value_node in node.value:
        key = _scalar(loader, key_node) if isinstance(key_node, yaml.ScalarNode) else None
        if not isinstance(key, str):
            errors.add(key_node, f"{what}: keys must be text")
            continue
        if key in out:
            errors.add(key_node, f"{what}: duplicate key '{key}'")
            continue
        if allowed and key not in allowed:
            hint = f" (allowed: {', '.join(allowed)})"
            errors.add(key_node, f"{what}: unknown key '{key}'{hint}")
            continue
        out[key] = (key_node, value_node)
    return out


def _string_list(loader: yaml.SafeLoader, node: yaml.Node, what: str, errors: _Errors,
                 pattern: re.Pattern[str] | None = None, pattern_hint: str = "") -> list[tuple[str, yaml.Node]]:
    if not isinstance(node, yaml.SequenceNode):
        errors.add(node, f"{what} must be a list, e.g. [a, b]")
        return []
    items = []
    for item in node.value:
        value = _scalar(loader, item) if isinstance(item, yaml.ScalarNode) else None
        if not isinstance(value, str) or not value.strip():
            errors.add(item, f"{what}: each entry must be non-empty text")
            continue
        value = value.strip()
        if pattern is not None and not pattern.match(value):
            errors.add(item, f"{what}: '{value}' is not {pattern_hint}")
            continue
        items.append((value, item))
    return items


def _text(loader: yaml.SafeLoader, node: yaml.Node, what: str, errors: _Errors) -> str | None:
    value = _scalar(loader, node) if isinstance(node, yaml.ScalarNode) else None
    if not isinstance(value, str) or not value.strip():
        errors.add(node, f"{what} must be non-empty text")
        return None
    return value.strip()


def _validate(loader: yaml.SafeLoader, root: yaml.Node, errors: _Errors) -> dict[str, Any]:
    model = _empty_model()
    lines: dict[str, int] = model["lines"]
    top = _mapping(loader, root, "the intent file", TOP_KEYS, errors)
    if top is None:
        return model

    if "version" not in top:
        errors.add(root, "'version: 1' is required")
    else:
        version = _scalar(loader, top["version"][1]) if isinstance(top["version"][1], yaml.ScalarNode) else None
        if version != SCHEMA_VERSION or isinstance(version, bool):
            errors.add(top["version"][1], f"version must be {SCHEMA_VERSION}")

    if "tgw_isolation" in top:
        matrix = _mapping(loader, top["tgw_isolation"][1], "tgw_isolation", (), errors) or {}
        for key, (key_node, value_node) in matrix.items():
            name = key.strip().lower()
            if not name:
                errors.add(key_node, "tgw_isolation: route table names must be non-empty")
                continue
            members = _string_list(loader, value_node, f"tgw_isolation.{key}", errors)
            model["tgw_isolation"][name] = sorted({m.lower() for m, _ in members})
            lines[f"tgw_isolation.{name}"] = key_node.start_mark.line + 1
            for member, node in members:
                lines.setdefault(f"tgw_isolation.{name}:{member.lower()}", node.start_mark.line + 1)

    if "dx_redundancy_pairs" in top:
        node = top["dx_redundancy_pairs"][1]
        if not isinstance(node, yaml.SequenceNode):
            errors.add(node, "dx_redundancy_pairs must be a list of {name, members}")
        else:
            seen: set[str] = set()
            for entry in node.value:
                fields = _mapping(loader, entry, "dx_redundancy_pairs entry", PAIR_KEYS, errors)
                if fields is None:
                    continue
                missing = [k for k in PAIR_KEYS if k not in fields]
                if missing:
                    errors.add(entry, f"dx_redundancy_pairs entry: missing {', '.join(missing)}")
                    continue
                name = _text(loader, fields["name"][1], "dx_redundancy_pairs.name", errors)
                members = _string_list(loader, fields["members"][1], f"dx_redundancy_pairs.{name}.members", errors,
                                       VIF_RE, "a VIF ID (dxvif-...)")
                ids = [m for m, _ in members]
                if name is None:
                    continue
                if name in seen:
                    errors.add(fields["name"][1], f"dx_redundancy_pairs: duplicate pair name '{name}'")
                    continue
                if len(ids) != 2 or len(set(ids)) != 2:
                    errors.add(fields["members"][1],
                               f"dx_redundancy_pairs.{name}.members must list exactly two different VIF IDs")
                    continue
                seen.add(name)
                model["dx_redundancy_pairs"].append({"name": name, "members": ids})
                lines[f"dx_redundancy_pairs.{name}"] = entry.start_mark.line + 1

    if "hybrid_paths" in top:
        node = top["hybrid_paths"][1]
        if not isinstance(node, yaml.SequenceNode):
            errors.add(node, "hybrid_paths must be a list of {prefix, exit_region | preferred | backup}")
        else:
            seen_prefixes: set[str] = set()
            for entry in node.value:
                fields = _mapping(loader, entry, "hybrid_paths entry", PATH_KEYS, errors)
                if fields is None:
                    continue
                if "prefix" not in fields:
                    errors.add(entry, "hybrid_paths entry: 'prefix' is required")
                    continue
                raw_prefix = _text(loader, fields["prefix"][1], "hybrid_paths.prefix", errors)
                if raw_prefix is None:
                    continue
                try:
                    prefix = str(ipaddress.ip_network(raw_prefix, strict=False))
                except ValueError:
                    errors.add(fields["prefix"][1], f"hybrid_paths: '{raw_prefix}' is not a CIDR, e.g. 10.0.0.0/16")
                    continue
                if not any(k in fields for k in ("exit_region", "preferred", "backup")):
                    errors.add(entry, f"hybrid_paths {prefix}: set at least one of exit_region, preferred, backup")
                    continue
                if prefix in seen_prefixes:
                    errors.add(fields["prefix"][1], f"hybrid_paths: prefix {prefix} is listed twice")
                    continue
                path: dict[str, str] = {"prefix": prefix}
                ok = True
                if "exit_region" in fields:
                    region = _text(loader, fields["exit_region"][1], f"hybrid_paths {prefix}: exit_region", errors)
                    if region is not None and not REGION_RE.match(region):
                        errors.add(fields["exit_region"][1], f"hybrid_paths {prefix}: '{region}' is not a Region code")
                        region = None
                    ok &= region is not None
                    if region:
                        path["exit_region"] = region
                for key in ("preferred", "backup"):
                    if key in fields:
                        value = _text(loader, fields[key][1], f"hybrid_paths {prefix}: {key}", errors)
                        if value is not None and not ATTACHMENT_RE.match(value.lower()):
                            errors.add(fields[key][1], f"hybrid_paths {prefix}: {key} '{value}' is not an attachment "
                                                       "or VIF ID (dxvif-, tgw-attach-, attachment-, vpn-)")
                            value = None
                        ok &= value is not None
                        if value:
                            path[key] = value.lower()
                if path.get("preferred") and path.get("preferred") == path.get("backup"):
                    errors.add(entry, f"hybrid_paths {prefix}: preferred and backup must differ")
                    ok = False
                if ok:
                    seen_prefixes.add(prefix)
                    model["hybrid_paths"].append(path)
                    lines[f"hybrid_paths.{prefix}"] = entry.start_mark.line + 1

    if "regions" in top:
        fields = _mapping(loader, top["regions"][1], "regions", REGION_KEYS, errors) or {}
        for key in REGION_KEYS:
            if key in fields:
                model["regions"][key] = sorted({r for r, _ in _string_list(
                    loader, fields[key][1], f"regions.{key}", errors, REGION_RE, "a Region code, e.g. eu-central-1")})
    return model


def parse(text: str, version_id: str | None = None) -> IntentLoad:
    """YAML + schema validation. Never raises on bad input."""
    loader = yaml.SafeLoader(text)
    try:
        root = loader.get_single_node()
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}: " if mark is not None else ""
        problem = getattr(exc, "problem", None) or type(exc).__name__
        return IntentLoad("rejected", version_id=version_id, errors=[f"{where}{problem}"])
    finally:
        pass
    if root is None:
        return IntentLoad("rejected", version_id=version_id, errors=["line 1: the intent file is empty"])
    errors = _Errors()
    try:
        model = _validate(loader, root, errors)
    except yaml.YAMLError as exc:  # e.g. an unknown tag such as !!python/object inside a value
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        line = mark.line + 1 if mark is not None else 1
        return IntentLoad("rejected", version_id=version_id,
                          errors=[f"line {line}: {getattr(exc, 'problem', None) or 'unsupported YAML'}"])
    finally:
        loader.dispose()
    if errors.items:
        return IntentLoad("rejected", version_id=version_id, errors=errors.sorted())
    return IntentLoad("ok", document=model, version_id=version_id)


def resolve_isolation(model: dict[str, Any], regions: dict[str, dict[str, Any]], tag_key: str) -> list[str]:
    """Every tgw_isolation key and member must name a collected route table: its ID, or the value of
    its `tag_key` tag on at least one table (case-insensitive). Returns 'line N: ...' errors."""
    from drift_core.snapshot import tag_value

    known: set[str] = set()
    for snap in regions.values():
        for table in snap.get("route_tables") or []:
            known.add(table["route_table_id"].lower())
            value = tag_value(table.get("tags") or {}, tag_key)
            if value:
                known.add(value.lower())
    lines = model.get("lines") or {}
    errors = []
    for key, members in sorted((model.get("tgw_isolation") or {}).items()):
        if key not in known:
            errors.append((lines.get(f"tgw_isolation.{key}", 1),
                           f"tgw_isolation: '{key}' matches no route table ID or {tag_key} tag value"))
        for member in members:
            if member not in known:
                errors.append((lines.get(f"tgw_isolation.{key}:{member}", lines.get(f"tgw_isolation.{key}", 1)),
                               f"tgw_isolation.{key}: '{member}' matches no route table ID or {tag_key} tag value"))
    return [f"line {line}: {text}" for line, text in sorted(errors)]
