# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool (opt-in write): create the agent's own Glue database, projection table and workgroup.

The only write to anything in the product, and only to resources the agent creates, tagged
``agent-managed: "true"``. Never modifies an existing table.
"""

from __future__ import annotations

from typing import Any

from ..core import s3layout
from ..core.athena import AthenaEngine
from ..core.tablescheme import ident, projection_ddl, scheme_for_created_table


def create_table(
    *,
    glue: Any,
    athena: Any,
    s3: Any,
    log_inventory: s3layout.LogInventory,
    first_day: str,
    agent_database: str,
    table: str,
    workgroup: str,
    results_location: str,
    confirmed: bool,
    fields_override: tuple[str, ...] | None = None,
    project: str = "network-flow-insight",
) -> dict:
    """Create the table, or describe what would be created when ``confirmed`` is false."""
    ident(agent_database), ident(table)
    fields = fields_override or s3layout.detect_fields(s3, log_inventory)
    accounts = sorted(log_inventory.accounts)
    regions = sorted(log_inventory.regions)
    ddl = projection_ddl(
        database=agent_database,
        table=table,
        bucket=log_inventory.bucket,
        fields=fields,
        accounts=accounts,
        regions=regions,
        first_day=first_day,
        layout=log_inventory.layout,  # type: ignore[arg-type]
        file_format=log_inventory.file_format,
        org_id=log_inventory.org_id,  # type: ignore[arg-type]
    )
    plan = {
        "database": agent_database,
        "table": table,
        "workgroup": workgroup,
        "results_location": results_location,
        "accounts": accounts,
        "regions": regions,
        "fields": list(fields),
        "layout": log_inventory.layout,
        "ddl": ddl,
        "tags": {"agent-managed": "true", "project": project},
    }
    if not confirmed:
        return {
            "status": "needs-confirmation",
            "plan": plan,
            "message": "Nothing was created. Confirm to create the Glue database, table and workgroup shown.",
        }
    try:
        glue.create_database(DatabaseInput={"Name": agent_database, "Parameters": {"agent-managed": "true"}})
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "AlreadyExistsException":
            raise
    try:
        athena.create_work_group(
            Name=workgroup,
            Configuration={
                "ResultConfiguration": {"OutputLocation": results_location},
                "EnforceWorkGroupConfiguration": True,
                "PublishCloudWatchMetricsEnabled": True,
            },
            Tags=[{"Key": "agent-managed", "Value": "true"}, {"Key": "project", "Value": project}],
        )
    except Exception as exc:
        if "already" not in str(exc).lower():
            raise
    eng = AthenaEngine(athena, workgroup, results_location, agent_database)
    res = eng.run(ddl)
    scheme = scheme_for_created_table(
        agent_database, table, fields, log_inventory.layout, log_inventory.file_format
    )
    return {
        "status": "created",
        "plan": plan,
        "execution_id": res.execution_id,
        "scheme": {k: (list(v) if isinstance(v, tuple) else v) for k, v in scheme.__dict__.items()},
    }
