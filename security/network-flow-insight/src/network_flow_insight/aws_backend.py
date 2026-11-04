# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Assemble a ``Backend`` over real AWS clients (Amazon S3, Athena, AWS Glue, CloudWatch, Price List).

Credentials come from the standard AWS credential chain. Everything read here is read-only except the
agent-managed database for the aggregate, which is created only when the caller confirms.
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Any

import boto3

from .analysis import Analysis, Backend
from .config import Settings
from .core import s3layout
from .core.athena import AthenaEngine, CostGauge, GaugedEngine
from .core.intent_schema import load_intent
from .tools import (
    build_aggregate,
    get_gateway_metrics,
    get_inventory,
    get_ip_ranges,
    get_prices,
    probe_table,
    query_cur,
    query_resolver_logs,
)

logger = logging.getLogger(__name__)


class SetupNeeded(RuntimeError):
    """Something must exist before analysis can run; carries what and how to proceed."""

    def __init__(self, message: str, plan: dict | None = None) -> None:
        super().__init__(message)
        self.plan = plan or {}


def make_session(settings: Settings) -> boto3.Session:
    return boto3.Session(region_name=settings.aws_region)


def _bucket_from_location(location: str) -> tuple[str, str]:
    if not location.startswith("s3://"):
        return "", ""
    bucket, _, rest = location[5:].partition("/")
    return bucket, rest


def build_backend(
    settings: Settings,
    first_day: str,
    last_day: str,
    *,
    session: boto3.Session | None = None,
    interactive: bool = True,
    confirm: Any = None,
    reference: dict | None = None,
    create_agent_resources: bool = False,
) -> Backend:
    sess = session or make_session(settings)
    s3, glue, athena = sess.client("s3"), sess.client("glue"), sess.client("athena")
    cw = sess.client("cloudwatch")

    rates = _rates(sess, settings)
    price_tb = rates.get("athena_per_tb")
    if not price_tb:
        raise SetupNeeded(
            "The Athena price per TB is unknown. Grant pricing:GetProducts or set NFI_ATHENA_PRICE_PER_TB "
            "(the cost gauge needs it)."
        )

    table_db, table_name = settings.flow_log_database, settings.flow_log_table
    if not table_name:
        found = probe_table.find_flow_log_tables(glue)
        if len(found) == 1:
            table_db, table_name = found[0]["database"], found[0]["table"]
        elif found:
            raise SetupNeeded(
                "Several flow-log tables exist; set NFI_FLOW_LOG_DATABASE and NFI_FLOW_LOG_TABLE.",
                {"candidates": found},
            )
        else:
            raise SetupNeeded(
                "No flow-log table found in the Glue catalog. Run `nfi create-table` (opt-in) to create one with "
                "partition projection over the bucket.",
                {"bucket": settings.flow_log_bucket},
            )
    bucket = settings.flow_log_bucket
    if not bucket:
        t = glue.get_table(DatabaseName=table_db, Name=table_name)["Table"]
        bucket, _ = _bucket_from_location(t["StorageDescriptor"].get("Location", ""))
    if not bucket:
        raise SetupNeeded("Cannot determine the flow-log bucket; set NFI_FLOW_LOG_BUCKET.")

    results = settings.athena_results_location or _workgroup_results(athena, settings.athena_workgroup)
    if not results:
        raise SetupNeeded(
            "No Athena results location; set NFI_ATHENA_RESULTS_LOCATION or configure the workgroup."
        )

    log_inv = s3layout.walk(s3, bucket, first_day, last_day, settings.flow_log_prefix)
    gauge = CostGauge(price_tb, settings.scan_ceiling_usd, settings.session_budget_usd)
    raw_engine = AthenaEngine(
        athena,
        settings.athena_workgroup,
        results,
        settings.agent_database,
        enforce_output=_enforced(athena, settings.athena_workgroup),
    )
    engine = GaugedEngine(raw_engine, gauge, interactive=interactive, confirm=confirm)
    probe = probe_table.probe_table(
        glue, table_db, table_name, first_day, last_day, engine=engine, log_inventory=log_inv
    )
    scheme = probe_table.scheme_from_dict(probe["scheme"])

    _ensure_agent_database(glue, settings.agent_database, create_agent_resources)

    letter, inv, note = _inventory(sess, settings)
    ranges = get_ip_ranges.get_ip_ranges(
        settings.ip_ranges_url,
        settings.ip_ranges_cache_dir or get_ip_ranges.default_cache_dir(),
        settings.ip_ranges_file,
        s3,
    )
    intent = load_intent(settings.intent_file, s3) if settings.intent_file else None

    def metrics_fn(gws: list[dict], a: str, b: str) -> Any:
        return get_gateway_metrics.get_gateway_metrics(cw, gws, a, b)

    cur_fn = resolver_fn = None
    if settings.cur_table:
        cur_engine = _assumed_engine(
            sess, settings, settings.cur_role_arn, gauge, interactive, confirm, settings.cur_workgroup
        )

        def cur_fn(a: str, b: str, accts: list[str]) -> Any:  # noqa: F811
            return query_cur.query_cur(cur_engine, settings.cur_database, settings.cur_table, a, b, accts)

    if settings.resolver_table:
        res_engine = _assumed_engine(
            sess, settings, settings.resolver_role_arn, gauge, interactive, confirm, settings.athena_workgroup
        )

        def resolver_fn(ips: list[str], a: str, b: str) -> Any:  # noqa: F811
            return query_resolver_logs.query_resolver_logs(
                res_engine, settings.resolver_database, settings.resolver_table, ips, a, b
            )

    def extend_log_inventory(a: str, b: str) -> None:
        log_inv.merge(s3layout.walk(s3, bucket, a, b, settings.flow_log_prefix))

    def find_agg(a: str, b: str, table: str | None = None) -> dict | None:
        return build_aggregate.find_aggregate(
            glue, settings.agent_database, a, b, settle_minutes=settings.aggregate_settle_minutes, table=table
        )

    return Backend(
        engine=engine,
        scheme=scheme,
        log_inventory=log_inv,
        visibility=probe["visibility_full"],
        dialect="trino",
        agg_database=settings.agent_database,
        results_prefix=results,
        inventory_provider=letter,
        inventory=inv,
        provider_note=note,
        ranges=ranges,
        rates=rates,
        intent=intent,
        home_region=settings.aws_region,
        metrics_fn=metrics_fn,
        cur_fn=cur_fn,
        resolver_fn=resolver_fn,
        find_aggregate_fn=find_agg,
        extend_log_fn=extend_log_inventory,
        reference=reference,
        read_parquet_fn=lambda location: read_parquet_location(s3, location),
        mode="aws",
        tables={
            "raw": f"{table_db}.{table_name}",
            "workgroup": settings.athena_workgroup,
            "results": results,
            "probe": {
                k: probe[k] for k in ("projection", "file_format", "recommendations", "skipdata_sample")
            },
        },
    )


def build_analysis(settings: Settings, first_day: str, last_day: str, **kw: Any) -> Analysis:
    return Analysis(settings, build_backend(settings, first_day, last_day, **kw))


def default_window(settings: Settings, today: date | None = None) -> tuple[str, str]:
    return s3layout.previous_complete_days(today or date.today(), settings.default_window_days)


def _rates(sess: boto3.Session, settings: Settings) -> dict:
    try:
        pricing = sess.client("pricing", region_name="us-east-1")
        rates = get_prices.get_prices(pricing, settings.aws_region)
    except Exception as exc:
        logger.warning('{"event": "pricing_unavailable", "error": "%s"}', str(exc)[:160])
        rates = {
            "region": settings.aws_region,
            "source": f"unavailable: {type(exc).__name__}",
            "athena_per_tb": None,
        }
    if settings.athena_price_per_tb:
        rates["athena_per_tb"] = settings.athena_price_per_tb
    return rates


def _workgroup_results(athena: Any, workgroup: str) -> str:
    try:
        wg = athena.get_work_group(WorkGroup=workgroup)["WorkGroup"]
        return wg["Configuration"].get("ResultConfiguration", {}).get("OutputLocation", "")
    except Exception:
        return ""


def _enforced(athena: Any, workgroup: str) -> bool:
    try:
        return bool(
            athena.get_work_group(WorkGroup=workgroup)["WorkGroup"]["Configuration"].get(
                "EnforceWorkGroupConfiguration"
            )
        )
    except Exception:
        return True  # assume enforced: omitting external_location is always accepted


def _ensure_agent_database(glue: Any, name: str, create: bool) -> None:
    try:
        glue.get_database(Name=name)
        return
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "EntityNotFoundException":
            raise
    if not create:
        raise SetupNeeded(
            f"The agent-managed Glue database '{name}' does not exist. It holds the aggregate table and is the only "
            "thing the agent creates. Re-run with --create-resources to create it.",
            {"database": name},
        )
    glue.create_database(DatabaseInput={"Name": name, "Parameters": {"agent-managed": "true"}})


def _inventory(sess: boto3.Session, settings: Settings):
    letter, inv, summary = get_inventory.get_inventory(
        settings.inventory_provider,
        session=sess,
        region=settings.aws_region,
        regions=[settings.aws_region],
        inventory_file=settings.inventory_file,
        aggregator=settings.config_aggregator,
    )
    return letter, inv, summary["note"]


def _assumed_engine(
    sess: boto3.Session,
    settings: Settings,
    role_arn: str,
    gauge: CostGauge,
    interactive: bool,
    confirm: Any,
    workgroup: str,
):
    athena = sess.client("athena")
    if role_arn:
        creds = sess.client("sts").assume_role(RoleArn=role_arn, RoleSessionName="network-flow-insight")[
            "Credentials"
        ]
        athena = boto3.client(
            "athena",
            region_name=settings.aws_region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    eng = AthenaEngine(athena, workgroup or settings.athena_workgroup, settings.athena_results_location, "")
    return GaugedEngine(eng, gauge, interactive=interactive, confirm=confirm)


def read_parquet_location(s3: Any, location: str) -> list[dict]:
    """Read every Parquet object under an S3 prefix into row dicts (the aggregate is small by design)."""
    import io

    import pyarrow.parquet as pq

    bucket, prefix = _bucket_from_location(location)
    prefix = (
        prefix if prefix.endswith("/") else prefix + "/"
    )  # a bare prefix also matches sibling manifest files
    rows: list[dict] = []
    token = None
    while True:
        kw: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        for obj in page.get("Contents", []):
            if obj["Size"] == 0 or obj["Key"].rsplit("/", 1)[-1].startswith(("_", ".")):
                continue
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            rows += pq.read_table(io.BytesIO(body)).to_pylist()
        if not page.get("IsTruncated"):
            return rows
        token = page["NextContinuationToken"]
