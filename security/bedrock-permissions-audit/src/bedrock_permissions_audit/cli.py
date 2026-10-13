# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Command-line entry point. Flags override the TOML file, which overrides the defaults."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .accounts import DiscoveryError
from .app import EXIT_CONFIG, run_audit
from .checkpoint import CheckpointError
from .config import ConfigError, load_config
from .log import configure_logging
from .output.terminal import render_report

# Settings with no command-line flag: lists that are awkward to type, set in the TOML file.
FILE_ONLY_SETTINGS = (
    "invoke_actions",
    "escalation_actions",
    "canary_actions",
    "admin_policy_arns",
    "representative_models",
    "scp_exception_principals",
)

DESCRIPTION = """\
Audit long-lived AWS credentials (IAM user access keys, root access keys, and Amazon Bedrock API
keys) that can invoke Amazon Bedrock models, and assign each a risk tier and a recommended action.
Read-only: nothing in any account is changed.

Run it from the organization's management account (or a delegated administrator) to audit every
member account, or from any single account. Output: a terminal report, findings.csv,
findings.json and suggested guard-rail policies in remediation/."""

EPILOG = (
    "Settings with no flag, available in the TOML file given to --config "
    "(see config/audit.example.toml): " + ", ".join(FILE_ONLY_SETTINGS) + ".\n\n"
    "Exit codes: 0 success (including partial account failures, which are listed in the "
    "summary), 2 configuration or credential error before any account was audited, "
    "3 no account could be audited."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bedrock-audit",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=Path, metavar="FILE", help="TOML configuration file.")

    scope = parser.add_argument_group("scope")
    scope.add_argument(
        "--mode",
        choices=("auto", "org", "single"),
        help="auto (default) tries the whole organization and falls back to this account.",
    )
    scope.add_argument(
        "--single-account",
        dest="mode",
        action="store_const",
        const="single",
        help="Audit only the account these credentials belong to (same as --mode single).",
    )
    scope.add_argument(
        "--role-name",
        metavar="NAME",
        help="Role assumed in each member account (default BedrockPermissionsAuditRole).",
    )
    scope.add_argument(
        "--external-id", metavar="ID", help="ExternalId for the audit role, if its trust needs one."
    )
    scope.add_argument(
        "--parallel-accounts",
        type=int,
        metavar="N",
        help="Accounts audited at once (default 8; 32 suits several hundred accounts).",
    )

    ranking = parser.add_argument_group("ranking")
    ranking.add_argument(
        "--dormant-days",
        type=int,
        metavar="N",
        help="A credential unused for, or older than, N days is dormant or old (default 90).",
    )
    ranking.add_argument(
        "--bedrock-regions",
        metavar="LIST",
        help="Comma-separated Regions where you use Amazon Bedrock (default: all Regions that "
        "offer it). Also used to generate the Region-restriction policy.",
    )
    ranking.add_argument(
        "--approved-models",
        metavar="LIST",
        help="Comma-separated model IDs you approve, used to generate the model-allowlist policy.",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "--output-dir",
        type=Path,
        metavar="DIR",
        help="Where to write results (default ./bedrock-audit-<UTC timestamp>/).",
    )
    output.add_argument(
        "--all",
        dest="show_all",
        action="store_true",
        default=None,
        help="Also list principals that cannot invoke Amazon Bedrock, and inactive keys that "
        "would not rate Critical or High if re-enabled.",
    )
    output.add_argument(
        "--unmask",
        action="store_true",
        default=None,
        help="Write full access key IDs to the CSV and JSON files (they are masked by default).",
    )
    output.add_argument(
        "--no-color", action="store_true", default=None, help="Disable colour in the terminal."
    )
    output.add_argument(
        "--resume",
        action="store_true",
        default=None,
        help="Continue an interrupted run in --output-dir, skipping accounts already completed.",
    )
    output.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Verbosity of the JSON log lines on stderr (default INFO).",
    )
    return parser


def overrides_from(args: argparse.Namespace) -> dict[str, object]:
    return {
        key: value
        for key, value in vars(args).items()
        if key not in {"config", "version"} and value is not None
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config, overrides_from(args))
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    configure_logging(config.log_level)
    try:
        outcome = run_audit(config)
    except (DiscoveryError, CheckpointError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        print(
            "\nInterrupted. Accounts already finished were saved; continue with --resume "
            "and the same --output-dir.",
            file=sys.stderr,
        )
        return 130

    color = sys.stdout.isatty() and not config.no_color and "NO_COLOR" not in os.environ
    sys.stdout.write(
        render_report(outcome.findings, outcome.summary, config, outcome.output_dir, color)
    )
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
