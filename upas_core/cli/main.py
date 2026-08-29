"""
UPAS CLI Main Entrypoint.
Provides the top-level command-line execution dispatcher and fail-closed error handling.
"""

import sys
from typing import List, Optional

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import (
    ProductionAuthError,
    UPASError,
)
from upas_core.cli.parser import SecurityViolationError, parse_cli_args
from upas_core.cli.runner import LifecycleHarness


def main(argv: Optional[List[str]] = None, harness: Optional[LifecycleHarness] = None) -> int:
    """
    Main entrypoint for the UPAS CLI.
    Guarantees that all failures and security violations return authoritative exit codes.
    """
    runner = harness or LifecycleHarness()

    try:
        args = parse_cli_args(argv)

        if args.command == "deploy":
            return runner.run_deploy(args)
        elif args.command == "verify":
            return runner.run_verify(args)
        elif args.command == "audit":
            return runner.run_audit(args)
        elif args.command == "preflight":
            return runner.run_preflight(args)
        elif args.command == "lock":
            return runner.run_lock(args)
        elif args.command == "discover":
            return runner.run_discover(args)
        elif args.command == "precheck":
            return runner.run_precheck(args)
        elif args.command == "init":
            return runner.run_init(args)
        else:
            sys.stderr.write(f"Unknown UPAS command: {args.command}\n")
            return ExitCode.TESTS_FAILED.value

    except SecurityViolationError as exc:
        sys.stderr.write(f"[UPAS SECURITY VIOLATION] {exc}\n")
        return exc.exit_code.value
    except ProductionAuthError as exc:
        sys.stderr.write(f"[UPAS AUTH ERROR] {exc}\n")
        return ExitCode.PROD_AUTH_FAILED.value
    except UPASError as exc:
        sys.stderr.write(f"[UPAS ERROR] {exc}\n")
        return exc.exit_code.value
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else ExitCode.TESTS_FAILED.value
    except Exception as exc:
        sys.stderr.write(f"[UPAS UNEXPECTED ERROR] {exc}\n")
        return ExitCode.TESTS_FAILED.value


if __name__ == "__main__":
    sys.exit(main())
