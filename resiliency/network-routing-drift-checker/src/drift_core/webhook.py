# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""DevOps Agent generic-webhook request: batching, description block, HMAC signing, POST.

Design refs: D§6.1 (request, priority, batching), D§6.2 (description block), D§11 (URL posture).
Webhook contract (DevOps Agent user guide, "Invoking DevOps Agent through Webhook", Version 1 / HMAC):
  headers  Content-Type: application/json
           x-amzn-event-timestamp: <%Y-%m-%dT%H:%M:%S.mmmZ>
           x-amzn-event-signature: base64(HMAC-SHA256(secret, f"{timestamp}:{body}"))
  body     eventType, incidentId, action, priority, title, description, timestamp, service, data
Only title, description and priority reach the agent; `data` is for our own correlation.

Batching, rendering and signing are precision code (no I/O, no clock). `post` is the only I/O.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

SIGNATURE_HEADER = "x-amzn-event-signature"
TIMESTAMP_HEADER = "x-amzn-event-timestamp"
SERVICE = "network-routing-drift-checker"
INCIDENT_PREFIX = "nrdc-"
TITLE_MAX = 250
LINE_MAX = 800

# https://event-ai.<region>.api.aws/webhook/generic/<id>, nothing else (no port, query, fragment, userinfo).
_URL_RE = re.compile(r"^https://event-ai\.(?P<region>[a-z]{2}(?:-[a-z]+)+-\d{1,2})\.api\.aws"
                     r"/webhook/generic/(?P<id>[A-Za-z0-9_-]{1,128})$")

# Kind families, in the tie-break order of D§6.3 (blackhole, redundancy, leak, wrong-domain, limit, hybrid-path).
KIND_ORDER = ("blackhole", "redundancy", "leak", "wrong-domain", "limit", "hybrid-path", "other")
_HIGH_KINDS = {"blackhole-route", "redundancy-member-missing", "redundancy-member-down", "redundancy-bgp-down",
               "redundancy-pair-down"}
_HIGH_LIMITS = {"dx-onprem-to-aws-per-bgp-session"}
# Resource IDs that make two findings "about the same thing" (D§6.1 resource-affine grouping).
_AFFINE_PREFIXES = ("tgw-rtb-", "tgw-attach-", "dxvif-", "attachment-", "vpn-", "dxcon-", "dxlag-",
                    "core-network-")


class WebhookError(Exception):
    """Base class. The class NAME becomes the Step Functions error name."""


class WebhookConfigError(WebhookError):
    """URL, Region or secret unusable. Fail closed; not retryable."""


class WebhookClientError(WebhookError):
    """4xx (or an unexpected redirect): authentication or payload problem. Not retryable."""


class WebhookServerError(WebhookError):
    """5xx from the webhook. Retryable."""


class WebhookTimeout(WebhookError):
    """No response within the timeout. Retryable."""


class WebhookTransportError(WebhookError):
    """Connection or TLS failure. Retryable."""


# --- URL ----------------------------------------------------------------------------------------

def validate_url(url: str) -> str:
    """Return the URL if it is a DevOps Agent generic webhook URL, else raise WebhookConfigError."""
    if not isinstance(url, str) or not _URL_RE.match(url):
        # Never echo the URL: it is on the redaction list and identifies the webhook.
        raise WebhookConfigError("webhook URL is not https://event-ai.<region>.api.aws/webhook/generic/<id>")
    return url


def webhook_region(url: str) -> str:
    """The Region embedded in a valid webhook URL (callers fail closed if it isn't theirs)."""
    validate_url(url)
    return _URL_RE.match(url).group("region")  # type: ignore[union-attr]  # validated above


# --- Classification -----------------------------------------------------------------------------

def kind_family(kind: str) -> str:
    kind = (kind or "").lower()
    if kind == "blackhole-route":
        return "blackhole"
    if kind.startswith("redundancy-"):
        return "redundancy"
    if kind.endswith("-leak"):
        return "leak"
    if kind in ("cloudwan-wrong-segment", "tgw-wrong-route-table"):
        return "wrong-domain"
    if kind.startswith("limit-"):
        return "limit"
    if kind.startswith("hybrid-path-"):
        return "hybrid-path"
    return "other"


def family_rank(kind: str) -> int:
    return KIND_ORDER.index(kind_family(kind))


def priority(findings: list[dict[str, Any]]) -> str:
    """HIGH if any blackhole, redundancy/BGP-down, or on-prem->AWS allocation limit finding; else MEDIUM."""
    for f in findings:
        kind = f.get("kind", "")
        if kind in _HIGH_KINDS:
            return "HIGH"
        if kind == "limit-threshold" and (f.get("context") or {}).get("limit_name") in _HIGH_LIMITS:
            return "HIGH"
    return "MEDIUM"


def investigable(new_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Only NEW *drift* findings are investigated; informational and system notes are not drift."""
    return [f for f in new_findings if f.get("severity") == "drift" and f.get("finding_id")]


def _is_prefix(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return "/" in value


def resource_keys(finding: dict[str, Any]) -> set[str]:
    """The resources a finding is about: IDs in its identity (and Cloud WAN table refs), plus its DX pair."""
    keys: set[str] = set()
    for raw in finding.get("identity") or []:
        value = str(raw).strip().lower()
        if not value or _is_prefix(value):
            continue
        if value.startswith(_AFFINE_PREFIXES):
            # A Cloud WAN table ref is 'core-network-x/segment/edge': one table, not the whole core network.
            keys.add(value)
    pair = (finding.get("context") or {}).get("pair")
    if pair:
        keys.add(f"pair:{str(pair).lower()}")
    return keys


def _order_key(f: dict[str, Any]) -> tuple:
    return (family_rank(f.get("kind", "")), f.get("kind", ""), f.get("region", ""), f["finding_id"])


def affinity_groups(findings: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Connected components of findings that share a resource key (union-find). Deterministic order."""
    ordered = sorted(findings, key=_order_key)
    parent = list(range(len(ordered)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, f in enumerate(ordered):
        for key in sorted(resource_keys(f)):
            if key in owner:
                a, b = find(i), find(owner[key])
                if a != b:
                    parent[max(a, b)] = min(a, b)
            else:
                owner[key] = i
    groups: dict[int, list[dict[str, Any]]] = {}
    for i, f in enumerate(ordered):
        groups.setdefault(find(i), []).append(f)
    return sorted(groups.values(), key=lambda g: (-len(g), _order_key(g[0])))


# --- Description block (D§6.2) ------------------------------------------------------------------

def incident_id(run_id: str, batch_n: int) -> str:
    return f"{INCIDENT_PREFIX}{run_id}-{batch_n}"


def investigation_tag(run_id: str, batch_n: int) -> str:
    return f"[INVESTIGATION_ID:{incident_id(run_id, batch_n)}]"


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _clip(line: str, limit: int = LINE_MAX) -> str:
    return line if len(line) <= limit else line[: limit - 14] + " …(truncated)"


def finding_block(f: dict[str, Any]) -> str:
    """One finding as the agent sees it. The '[n] ' index is added by `render_description`."""
    context = {k: v for k, v in (f.get("context") or {}).items() if v not in (None, "", [], {})}
    lines = [
        f"id={f['finding_id']} kind={f.get('kind')} region={f.get('region')} check={f.get('check')}",
        f"    {_clip(str(f.get('message') or ''))}",
        _clip(f"    expected: {_compact(f.get('expected') or {})}  observed: {_compact(f.get('observed') or {})}"),
        _clip(f"    context: {_compact(context)}"),
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class RunContext:
    run_id: str
    account_id: str
    started_at: str
    lookback_from: str


def _header(ctx: RunContext, batch_n: int, batches: int) -> str:
    return "\n".join([
        investigation_tag(ctx.run_id, batch_n),
        f"NETWORK ROUTING DRIFT — NEW FINDINGS (run {ctx.run_id}, lookback from {ctx.lookback_from})",
        # Explicit `+` so this reads as one list element, not two.
        f"Account {ctx.account_id}. Batch {batch_n} of {batches}. "
        + "Skill to apply: network-routing-drift (with aws-routing).",
        "Return the structured result block defined by the skill, covering exactly the finding IDs below.",
        "",
    ])


def _footer(ctx: RunContext) -> str:
    return f"Lookback window for change events: {ctx.lookback_from} → {ctx.started_at}."


def render_description(ctx: RunContext, batch_n: int, batches: int, blocks: list[str]) -> str:
    body = [f"[{i}] {block}" for i, block in enumerate(blocks, start=1)]
    return "\n".join([_header(ctx, batch_n, batches), *body, _footer(ctx)])


def _bytes(text: str) -> int:
    return len(text.encode("utf-8"))


@dataclass
class Batch:
    batch_n: int
    batches: int
    incident_id: str
    priority: str
    title: str
    description: str
    finding_ids: list[str]
    finding_kinds: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"batch_n": self.batch_n, "batches": self.batches, "incident_id": self.incident_id,
                "priority": self.priority, "title": self.title, "description": self.description,
                "finding_ids": self.finding_ids, "finding_kinds": self.finding_kinds}


def _title(findings: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("kind", "?")] = counts.get(f.get("kind", "?"), 0) + 1
    kinds = ", ".join(f"{n} {k}" for k, n in sorted(counts.items(), key=lambda kv: (family_rank(kv[0]), kv[0])))
    noun = "finding" if len(findings) == 1 else "findings"
    return _clip(f"Network routing drift: {len(findings)} new {noun} ({kinds})", TITLE_MAX)


def make_batches(findings: list[dict[str, Any]], ctx: RunContext, max_findings: int,
                 max_description_bytes: int) -> list[Batch]:
    """Split NEW drift findings into investigations (D§6.1).

    Findings that share a resource stay together; a group larger than `max_findings` is split in
    order. Each batch holds at most `max_findings` findings and a description of at most
    `max_description_bytes` bytes. Groups are placed first-fit, largest first.
    """
    if max_findings < 1:
        raise ValueError("max_findings must be >= 1")
    # Worst-case header/footer and index width, so a batch never grows past the cap when numbered.
    overhead = _bytes(_header(ctx, 99999, 99999)) + _bytes(_footer(ctx)) + 1
    budget = max_description_bytes - overhead
    index_width = len(f"[{max_findings}] ") + 1
    if budget < 512:
        raise ValueError("max_description_bytes leaves no room for findings")

    blocks: dict[str, str] = {}
    for f in findings:
        block = finding_block(f)
        if _bytes(block) + index_width > budget:
            block = block.encode("utf-8")[: budget - index_width - 20].decode("utf-8", "ignore") + " …(truncated)"
        blocks[f["finding_id"]] = block

    def size(group: list[dict[str, Any]]) -> int:
        return sum(_bytes(blocks[f["finding_id"]]) + index_width for f in group)

    chunks: list[list[dict[str, Any]]] = []
    for group in affinity_groups(findings):
        current: list[dict[str, Any]] = []
        for f in group:
            if current and (len(current) >= max_findings or size(current) + size([f]) > budget):
                chunks.append(current)
                current = []
            current.append(f)
        if current:
            chunks.append(current)

    bins: list[list[dict[str, Any]]] = []
    for chunk in chunks:
        for b in bins:
            if len(b) + len(chunk) <= max_findings and size(b) + size(chunk) <= budget:
                b.extend(chunk)
                break
        else:
            bins.append(list(chunk))

    total = len(bins)
    result: list[Batch] = []
    for n, members in enumerate(bins, start=1):
        members.sort(key=_order_key)
        description = render_description(ctx, n, total, [blocks[f["finding_id"]] for f in members])
        result.append(Batch(
            batch_n=n, batches=total, incident_id=incident_id(ctx.run_id, n), priority=priority(members),
            title=_title(members), description=description,
            finding_ids=[f["finding_id"] for f in members],
            finding_kinds={f["finding_id"]: f.get("kind", "") for f in members}))
    return result


# --- Request + signature ------------------------------------------------------------------------

def timestamp(now: dt.datetime) -> str:
    """'%Y-%m-%dT%H:%M:%S.mmmZ' in UTC, the format the webhook docs specify."""
    now = now.astimezone(dt.UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def sign(secret: str, ts: str, body: str) -> str:
    """base64(HMAC-SHA256(secret, f'{ts}:{body}'))."""
    digest = hmac.new(secret.encode("utf-8"), f"{ts}:{body}".encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def build_body(batch: dict[str, Any], run_id: str, ts: str) -> str:
    payload = {
        "eventType": "incident",
        "incidentId": batch["incident_id"],
        "action": "created",
        "priority": batch["priority"],
        "title": batch["title"],
        "description": batch["description"],
        "timestamp": ts,
        "service": SERVICE,
        "data": {"run_id": run_id, "batch": batch["batch_n"], "batches": batch["batches"]},
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def signed_headers(secret: str, ts: str, body: str) -> dict[str, str]:
    return {"Content-Type": "application/json", TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sign(secret, ts, body)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the request may only reach the validated webhook host."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def post(url: str, body: str, headers: dict[str, str], timeout: float) -> int:
    """POST the signed body. Returns the HTTP status (2xx). Raises a WebhookError subclass otherwise."""
    validate_url(url)  # https-only, one host family (Bandit B310 posture)
    request = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")  # noqa: S310
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        code = exc.code
        if 500 <= code <= 599:
            raise WebhookServerError(f"webhook returned HTTP {code}") from None
        raise WebhookClientError(f"webhook returned HTTP {code}") from None
    except TimeoutError:
        raise WebhookTimeout(f"no response from the webhook within {timeout:g} s") from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise WebhookTimeout(f"no response from the webhook within {timeout:g} s") from None
        raise WebhookTransportError(f"could not reach the webhook ({type(exc.reason).__name__})") from None
    except OSError as exc:
        raise WebhookTransportError(f"could not reach the webhook ({type(exc).__name__})") from None
