"""
UPAS Shared Infrastructure Mutation Guard.
Implements the InfrastructureGuard protocol.
Enforces Invariant 3: External Shared Infrastructure Read-Only Boundary (Exit Code 77).
Enforces Security Invariant: UNKNOWN = FAIL.
"""

from typing import Dict, List, Optional, Set
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import SharedInfraViolationError
from upas_core.contracts.interfaces import InfrastructureGuard
from upas_core.contracts.results import GuardResult

_DEFAULT_SHARED_RESOURCES: Set[str] = {
    "shared-postgres",
    "shared-redis",
    "shared_postgres",
    "shared_redis",
    "postgres",
    "redis",
    "traefik",
    "server-infrastructure",
    "shared-database",
    "shared-cache",
}

_READONLY_MODES: Set[str] = {
    "read",
    "readonly",
    "readonly_consumer",
    "inspect",
    "query",
    "status",
    "health_check",
    "logs",
    "get",
    "describe",
    "ping",
    "select",
}

_MUTATION_MODES: Set[str] = {
    "write",
    "mutate",
    "restart",
    "stop",
    "remove",
    "recreate",
    "modify",
    "update",
    "delete",
    "start",
    "exec",
    "scale",
    "pause",
    "unpause",
    "down",
    "up",
    "compose",
    "kill",
    "deploy",
    "insert",
    "drop",
    "alter",
}


class SharedInfrastructureGuard(InfrastructureGuard):
    """
    Enforces that applications can only consume external shared infrastructure
    in read-only mode, and never mutate, restart, or recreate shared resources.
    Implements strict fail-closed boundary enforcement (UNKNOWN = FAIL).
    """

    def __init__(
        self,
        shared_resources: Optional[Set[str]] = None,
        local_resources: Optional[Set[str]] = None,
    ):
        self.shared_resources = {
            r.strip().lower() for r in (shared_resources if shared_resources is not None else _DEFAULT_SHARED_RESOURCES)
        }
        self.local_resources = {
            r.strip().lower() for r in (local_resources or set())
        }

    @classmethod
    def from_adapter_config(
        cls,
        infrastructure_dependencies: Optional[List[Dict[str, str]]] = None,
        project_name: Optional[str] = None,
        local_resources: Optional[Set[str]] = None,
    ) -> "SharedInfrastructureGuard":
        """Builds guard instance from adapter configuration declarations."""
        shared_set = set(_DEFAULT_SHARED_RESOURCES)
        if infrastructure_dependencies:
            for dep in infrastructure_dependencies:
                dep_name = dep.get("name")
                if dep_name:
                    shared_set.add(dep_name.strip().lower())

        local_set = set(local_resources or set())
        if project_name:
            local_set.add(project_name.strip().lower())

        return cls(shared_resources=shared_set, local_resources=local_set)

    def check_boundary(self, target_resource: str, access_mode: str) -> GuardResult:
        """
        Evaluates whether the requested access mode on the target resource is permitted.
        Returns GuardResult with ExitCode.SUCCESS if permitted, or ExitCode.SHARED_INFRA_VIOLATION if blocked.
        """
        # 1. Reject empty or invalid inputs
        if not target_resource or not isinstance(target_resource, str) or not target_resource.strip():
            return GuardResult(
                allowed=False,
                target_resource=str(target_resource),
                access_mode=str(access_mode),
                violation_type="INVALID_RESOURCE",
                error_message="Target resource cannot be empty or non-string",
                exit_code=ExitCode.SHARED_INFRA_VIOLATION,
            )

        if not access_mode or not isinstance(access_mode, str) or not access_mode.strip():
            return GuardResult(
                allowed=False,
                target_resource=target_resource,
                access_mode=str(access_mode),
                violation_type="INVALID_ACCESS_MODE",
                error_message="Access mode cannot be empty or non-string",
                exit_code=ExitCode.SHARED_INFRA_VIOLATION,
            )

        norm_resource = target_resource.strip().lower()
        norm_mode = access_mode.strip().lower()

        # 2. Check if access mode is recognized
        is_readonly = norm_mode in _READONLY_MODES
        is_mutation = norm_mode in _MUTATION_MODES

        if not is_readonly and not is_mutation:
            return GuardResult(
                allowed=False,
                target_resource=target_resource,
                access_mode=access_mode,
                violation_type="UNKNOWN_ACCESS_MODE",
                error_message=(
                    f"Unknown or unclassified access mode '{access_mode}'. "
                    f"Safety cannot be proven (UNKNOWN = FAIL)."
                ),
                exit_code=ExitCode.SHARED_INFRA_VIOLATION,
            )

        # 3. Check if target is a known shared external resource
        is_shared = (
            norm_resource in self.shared_resources
            or any(norm_resource.startswith(f"{s}/") or norm_resource == s for s in self.shared_resources)
        )

        if is_shared:
            if is_readonly:
                return GuardResult(
                    allowed=True,
                    target_resource=target_resource,
                    access_mode=access_mode,
                    exit_code=ExitCode.SUCCESS,
                )
            else:
                return GuardResult(
                    allowed=False,
                    target_resource=target_resource,
                    access_mode=access_mode,
                    violation_type="SHARED_INFRA_MUTATION_FORBIDDEN",
                    error_message=(
                        f"Mutation of shared infrastructure '{target_resource}' via mode '{access_mode}' "
                        f"is strictly forbidden by UPAS contract (readonly_consumer only)."
                    ),
                    exit_code=ExitCode.SHARED_INFRA_VIOLATION,
                )

        # 4. Check if target is an explicitly declared local resource
        is_local = (
            norm_resource in self.local_resources
            or any(norm_resource.startswith(f"{loc}/") or norm_resource == loc for loc in self.local_resources)
        )

        if is_local:
            return GuardResult(
                allowed=True,
                target_resource=target_resource,
                access_mode=access_mode,
                exit_code=ExitCode.SUCCESS,
            )

        # 5. Security Invariant: UNKNOWN = FAIL
        return GuardResult(
            allowed=False,
            target_resource=target_resource,
            access_mode=access_mode,
            violation_type="UNKNOWN_INFRASTRUCTURE_RESOURCE",
            error_message=(
                f"Unknown infrastructure target resource '{target_resource}'. "
                f"Safety cannot be established (UNKNOWN = FAIL)."
            ),
            exit_code=ExitCode.SHARED_INFRA_VIOLATION,
        )


def verify_infrastructure_boundary(
    target_resource: str,
    access_mode: str,
    guard: Optional[InfrastructureGuard] = None,
) -> None:
    """
    Fail-closed gate function for infrastructure boundary check.
    Raises SharedInfraViolationError (exit code 77) if access is blocked.
    """
    guard = guard or SharedInfrastructureGuard()
    result = guard.check_boundary(target_resource, access_mode)
    if not result.allowed:
        raise SharedInfraViolationError(result.error_message or "Shared infrastructure boundary violation")
