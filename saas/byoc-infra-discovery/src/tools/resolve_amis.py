# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tool: AMI IDs for a region.

Primary path: public SSM AMI parameters (canonical / AL2023) when readable.
Fallback: live ec2:DescribeImages (dated Ubuntu names) when the region is enabled.

For non-enabled regions where no AMI can be found, ami_available is False and the
absence is reported as a FACT (not an error) — this drives the deployability
blocker "no-ami-published". Pure code, no LLM.
"""

from typing import Optional

from strands import tool

from cache import get_or_compute
from tools._common import (
    CONFIDENCE_HIGH,
    SOURCE_EC2_LIVE,
    SOURCE_SSM_PUBLIC_PARAM,
    ec2_client,
    require_region,
    ssm_regional_client,
)
from tools._resilience import try_live

# Canonical (Ubuntu) owner id.
_DEFAULT_OWNER = "099720109477"
_DEFAULT_NAME_PATTERN = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"


def _ssm_public_ami(region: str, ssm_param: str) -> Optional[dict]:
    def _call() -> Optional[dict]:
        resp = ssm_regional_client(region).get_parameter(Name=ssm_param)
        return {"id": resp["Parameter"]["Value"], "name": ssm_param}

    return try_live(_call, dataset="amis", region=region)


def _live_images(region: str, name_pattern: str, owner: str) -> Optional[list[dict]]:
    def _call() -> list[dict]:
        resp = ec2_client(region).describe_images(
            Owners=[owner],
            Filters=[{"Name": "name", "Values": [name_pattern]}],
        )
        images = sorted(
            resp.get("Images", []),
            key=lambda i: i.get("CreationDate", ""),
            reverse=True,
        )
        return [{"id": i["ImageId"], "name": i.get("Name")} for i in images]

    return try_live(_call, dataset="amis", region=region)


def resolve_amis_impl(
    region: str,
    name_pattern: Optional[str] = None,
    owner: Optional[str] = None,
    ssm_param: Optional[str] = None,
) -> dict:
    """Core logic (testable without the Strands runtime)."""
    region = require_region(region)
    pattern = (
        name_pattern.strip()
        if isinstance(name_pattern, str) and name_pattern.strip()
        else _DEFAULT_NAME_PATTERN
    )
    own = owner.strip() if isinstance(owner, str) and owner.strip() else _DEFAULT_OWNER

    def _compute() -> dict:
        # Prefer a public SSM parameter if one was requested (readable globally
        # when the parameter is public), else live describe-images.
        if ssm_param:
            ssm_hit = _ssm_public_ami(region, ssm_param)
            if ssm_hit:
                return {
                    "region": region,
                    "amis": [ssm_hit],
                    "ami_available": True,
                    "source": SOURCE_SSM_PUBLIC_PARAM,
                    "confidence": CONFIDENCE_HIGH,
                }

        images = _live_images(region, pattern, own)
        if images:
            return {
                "region": region,
                "amis": images,
                "ami_available": True,
                "source": SOURCE_EC2_LIVE,
                "confidence": CONFIDENCE_HIGH,
            }
        # No AMI found (common for non-enabled / new opt-in regions).
        # Absence is a fact, not an error.
        return {
            "region": region,
            "amis": [],
            "ami_available": False,
            "source": SOURCE_EC2_LIVE,
            "confidence": CONFIDENCE_HIGH,
        }

    return get_or_compute(
        "amis",
        _compute,
        region=region,
        params={"pattern": pattern, "owner": own, "ssm_param": ssm_param},
    )


@tool
def resolve_amis(
    region: str,
    name_pattern: Optional[str] = None,
    owner: Optional[str] = None,
    ssm_param: Optional[str] = None,
) -> dict:
    """Return AMI IDs for a region.

    Tries a public SSM AMI parameter first (if ssm_param given), then live
    Amazon EC2 describe-images. When no AMI can be found (common for non-enabled
    or newly launched opt-in regions), returns ami_available=false and an empty
    list — the absence is a fact used by deployability checks, not an error.

    Args:
        region: region code.
        name_pattern: AMI name filter (default: Ubuntu 24.04 noble amd64 server).
        owner: AMI owner account id (default: Canonical, 099720109477).
        ssm_param: optional public SSM parameter name for a canonical AMI.

    Returns:
        {"region", "amis": [{"id","name"}], "ami_available", "source",
         "confidence"}
    """
    return resolve_amis_impl(region, name_pattern, owner, ssm_param)
