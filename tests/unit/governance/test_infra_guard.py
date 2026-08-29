"""
Unit tests for UPAS Shared Infrastructure Guard.
Tests boundary enforcement, read-only vs mutation modes, and fail-closed gates.
"""

import pytest
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import SharedInfraViolationError
from upas_core.governance.infra_guard import (
    SharedInfrastructureGuard,
    verify_infrastructure_boundary,
)


def test_shared_infra_readonly_access_allowed():
    guard = SharedInfrastructureGuard(
        shared_resources={"shared-postgres", "shared-redis"},
        local_resources={"support_bot_app"},
    )

    res_read = guard.check_boundary("shared-postgres", "read")
    assert res_read.allowed is True
    assert res_read.exit_code == ExitCode.SUCCESS

    res_health = guard.check_boundary("shared-redis", "health_check")
    assert res_health.allowed is True
    assert res_health.exit_code == ExitCode.SUCCESS


def test_shared_infra_mutation_forbidden():
    guard = SharedInfrastructureGuard(
        shared_resources={"shared-postgres", "shared-redis"},
        local_resources={"support_bot_app"},
    )

    forbidden_modes = ["write", "restart", "stop", "recreate", "remove", "drop", "alter"]
    for mode in forbidden_modes:
        res = guard.check_boundary("shared-postgres", mode)
        assert res.allowed is False
        assert res.exit_code == ExitCode.SHARED_INFRA_VIOLATION
        assert res.violation_type == "SHARED_INFRA_MUTATION_FORBIDDEN"


def test_local_resource_access_allowed():
    guard = SharedInfrastructureGuard(
        shared_resources={"shared-postgres"},
        local_resources={"support_bot_app"},
    )

    # Local resource mutation and read are both allowed
    res_mutate = guard.check_boundary("support_bot_app", "restart")
    assert res_mutate.allowed is True
    assert res_mutate.exit_code == ExitCode.SUCCESS


def test_verify_infrastructure_boundary_raises_exception():
    guard = SharedInfrastructureGuard(shared_resources={"shared-postgres"})

    # Read passes
    verify_infrastructure_boundary("shared-postgres", "read", guard=guard)

    # Mutation raises SharedInfraViolationError (exit code 77)
    with pytest.raises(SharedInfraViolationError) as exc_info:
        verify_infrastructure_boundary("shared-postgres", "restart", guard=guard)
    assert exc_info.value.exit_code == ExitCode.SHARED_INFRA_VIOLATION
