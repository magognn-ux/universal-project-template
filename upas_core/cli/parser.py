"""
UPAS Unified CLI Argument Parser & Security Gatekeeper.
Strictly parses commands while blocking any local bypass flags (--force, --approve, --no-auth, etc.).
"""

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import UPASError


class SecurityViolationError(UPASError):
    """Raised when an attempt is made to bypass security, authorization, or safety gates."""
    def __init__(self, message: str):
        super().__init__(message, exit_code=ExitCode.PROD_AUTH_FAILED)


# Prohibited bypass flags that violate the zero-bypass security invariant
FORBIDDEN_BYPASS_FLAGS = {
    "--force",
    "-f",
    "--approve",
    "--skip-auth",
    "--no-auth",
    "--bypass-auth",
    "--bypass-lock",
    "--skip-lock",
    "--skip-backup",
    "--no-backup",
    "--skip-verify",
    "--skip-verification",
    "--insecure",
    "--ignore-errors",
    "--dry-run-mutate",
    "--allow-unauthorized",
}


def detect_security_bypass_attempts(argv: List[str]) -> None:
    """
    Scans raw arguments for prohibited bypass flags before argument parsing.
    Raises SecurityViolationError (Exit Code 43 - PROD_AUTH_FAILED) if any bypass flag is present.
    """
    for arg in argv:
        normalized_arg = arg.strip().lower().split("=")[0]
        if normalized_arg in FORBIDDEN_BYPASS_FLAGS:
            raise SecurityViolationError(
                f"Prohibited bypass flag '{arg}' detected. "
                f"UPAS zero-bypass security invariant strictly prohibits local override flags."
            )


class StrictArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser with deterministic error handling and exit codes."""

    def error(self, message: str):
        # Fail closed on malformed syntax
        sys.stderr.write(f"UPAS CLI Syntax Error: {message}\n")
        sys.exit(ExitCode.TESTS_FAILED.value)


def build_upas_parser() -> argparse.ArgumentParser:
    """Constructs the unified UPAS CLI argument parser."""
    parser = StrictArgumentParser(
        prog="upas",
        description="Universal Project Automation Standard (UPAS) — Unified Lifecycle CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="UPAS Subcommands")

    # 1. 'deploy' Subcommand
    deploy_parser = subparsers.add_parser(
        "deploy",
        help="Execute authoritative full production deployment lifecycle",
    )
    deploy_parser.add_argument(
        "--adapter",
        dest="adapter_path",
        default="upas.adapter.json",
        help="Path to upas.adapter.json contract file (default: upas.adapter.json)",
    )
    deploy_parser.add_argument(
        "--artifact",
        dest="artifact_path",
        help="Path to artifact.json descriptor file",
    )
    deploy_parser.add_argument(
        "--canonical-reference",
        dest="canonical_reference",
        help="Canonical image reference with immutable digest (e.g. registry/app@sha256:...)",
    )
    deploy_parser.add_argument(
        "--digest",
        dest="digest",
        help="Immutable sha256 artifact digest",
    )
    deploy_parser.add_argument(
        "--commit-sha",
        dest="commit_sha",
        help="Source commit SHA for artifact provenance",
    )
    deploy_parser.add_argument(
        "--branch",
        dest="branch",
        default="main",
        help="Source branch for artifact provenance (default: main)",
    )
    deploy_parser.add_argument(
        "--oidc-token",
        dest="oidc_token",
        help="GitHub Actions OIDC JWT token string (or via UPAS_OIDC_TOKEN env var)",
    )
    deploy_parser.add_argument(
        "--expected-repository",
        dest="expected_repository",
        help="Expected repository name for OIDC validation",
    )
    deploy_parser.add_argument(
        "--expected-environment",
        dest="expected_environment",
        default="production",
        help="Expected environment claim for OIDC validation (default: production)",
    )
    deploy_parser.add_argument(
        "--output-evidence",
        dest="evidence_output_path",
        help="Output filepath for verified canonical evidence JSON",
    )
    deploy_parser.add_argument(
        "--output-manifest",
        dest="manifest_output_path",
        help="Output filepath for cryptographic evidence manifest JSON",
    )

    # 2. 'verify' Subcommand
    verify_parser = subparsers.add_parser(
        "verify",
        help="Execute post-deployment runtime verification and smoke testing",
    )
    verify_parser.add_argument(
        "--adapter",
        dest="adapter_path",
        default="upas.adapter.json",
        help="Path to upas.adapter.json contract file",
    )
    verify_parser.add_argument(
        "--running-digest",
        dest="running_digest",
        help="Live container running digest to verify against approved digest",
    )
    verify_parser.add_argument(
        "--approved-digest",
        dest="approved_digest",
        help="Expected approved immutable digest",
    )

    # 3. 'audit' Subcommand
    audit_parser = subparsers.add_parser(
        "audit",
        help="Verify cryptographic integrity of persisted evidence and manifest",
    )
    audit_parser.add_argument(
        "--evidence",
        dest="evidence_path",
        required=True,
        help="Path to .evidence.json file",
    )
    audit_parser.add_argument(
        "--manifest",
        dest="manifest_path",
        required=True,
        help="Path to .manifest.json file",
    )

    # 4. 'preflight' Subcommand
    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Run standalone resource preflight inspection gate",
    )
    preflight_parser.add_argument(
        "--adapter",
        dest="adapter_path",
        default="upas.adapter.json",
        help="Path to upas.adapter.json contract file",
    )

    # 5. 'lock' Subcommand
    lock_parser = subparsers.add_parser(
        "lock",
        help="Inspect or test host deployment concurrency lock",
    )
    lock_parser.add_argument(
        "--path",
        dest="lock_path",
        default="/run/lock/upas-deploy.lock",
        help="Host lock filepath (default: /run/lock/upas-deploy.lock)",
    )
    lock_parser.add_argument(
        "--check",
        dest="check_only",
        action="store_true",
        help="Check whether host lock is currently held",
    )

    # 6. 'discover' Subcommand
    discover_parser = subparsers.add_parser(
        "discover",
        help="Discover project adapter and validate declared capabilities",
    )
    discover_parser.add_argument(
        "--project",
        dest="project_dir",
        default=".",
        help="Path to project directory (default: .)",
    )
    discover_parser.add_argument(
        "--adapter",
        dest="adapter_path",
        help="Optional explicit path to upas.adapter.json",
    )

    # 7. 'precheck' / 'test' Subcommand
    precheck_parser = subparsers.add_parser(
        "precheck",
        help="Execute QA release precheck and targeted test budget runner",
    )
    precheck_parser.add_argument(
        "--adapter",
        dest="adapter_path",
        default="upas.adapter.json",
        help="Path to upas.adapter.json contract file",
    )
    precheck_parser.add_argument(
        "--project",
        dest="project_dir",
        default=".",
        help="Path to project directory (default: .)",
    )
    precheck_parser.add_argument(
        "--files",
        dest="files",
        help="Comma-separated list of modified file paths for targeted testing",
    )
    precheck_parser.add_argument(
        "--force-level",
        dest="force_level",
        type=int,
        choices=[0, 1, 2, 3, 4, 5],
        help="Enforce minimum test tier level (0-5)",
    )

    # 8. 'init' Subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Bootstrap canonical UPAS adapter and caller workflow for a project",
    )
    init_parser.add_argument(
        "--project",
        dest="project_dir",
        default=".",
        help="Path to project directory (default: .)",
    )
    init_parser.add_argument(
        "--name",
        dest="custom_name",
        help="Override declared project name",
    )
    init_parser.add_argument(
        "--archetype",
        dest="archetype",
        choices=["application", "infrastructure", "library"],
        default="application",
        help="Project archetype (application, infrastructure, library; default: application)",
    )
    init_parser.add_argument(
        "--overwrite",
        dest="overwrite",
        action="store_true",
        help="Safely overwrite existing conflicting files",
    )

    return parser


def parse_cli_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parses command-line arguments while guaranteeing bypass security enforcement.
    """
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    
    # 1. Strictly scan for prohibited bypass flags
    detect_security_bypass_attempts(raw_args)

    # 2. Parse using strict parser
    parser = build_upas_parser()
    return parser.parse_args(raw_args)
