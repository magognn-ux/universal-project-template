"""
Adversarial Tests for UPAS Shared Infrastructure Mutation Guard.
Covers threat models T-V:
  T. Shared infrastructure mutation attempts (restart/stop/recreate/write)
  U. Unknown infrastructure target (UNKNOWN = FAIL invariant)
  V. Read-only shared infrastructure access
"""

import pytest
from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import SharedInfraViolationError
from upas_core.governance.infra_guard import (
    SharedInfrastructureGuard,
    verify_infrastructure_boundary,
)


# T. Shared infrastructure mutation attempt
def test_adversarial_T_shared_infrastructure_mutation_attempts_blocked():
    guard = SharedInfrastructureGuard(
        shared_resources={"shared-postgres", "shared-redis", "traefik", "server-infrastructure"},
        local_resources={"tour_monitor_web", "support_bot"},
    )

    attack_scenarios = [
        ("shared-postgres", "restart"),
        ("shared-postgres", "stop"),
        ("shared-postgres", "remove"),
        ("shared-postgres", "recreate"),
        ("shared-postgres", "write"),
        ("shared-postgres", "compose"),
        ("shared-postgres", "drop"),
        ("shared-postgres", "alter"),
        ("shared-redis", "restart"),
        ("shared-redis", "modify"),
        ("shared-redis", "delete"),
        ("traefik", "restart"),
        ("traefik", "down"),
        ("server-infrastructure", "deploy"),
    ]

    for resource, mode in attack_scenarios:
        res = guard.check_boundary(resource, mode)
        assert res.allowed is False, f"Expected {resource} with mode {mode} to be BLOCKED"
        assert res.exit_code == ExitCode.SHARED_INFRA_VIOLATION
        assert res.violation_type == "SHARED_INFRA_MUTATION_FORBIDDEN"

        with pytest.raises(SharedInfraViolationError) as exc_info:
            verify_infrastructure_boundary(resource, mode, guard=guard)
        assert exc_info.value.exit_code == ExitCode.SHARED_INFRA_VIOLATION


# U. Unknown infrastructure target (UNKNOWN = FAIL)
def test_adversarial_U_unknown_infrastructure_target_fails_closed():
    guard = SharedInfrastructureGuard(
        shared_resources={"shared-postgres"},
        local_resources={"support_bot"},
    )

    unknown_targets = [
        "unregistered-service",
        "external-unknown-db",
        "legacy-monolith-backend",
        "kubernetes-cluster-control-plane",
        "production-edge-gateway",
    ]

    for target in unknown_targets:
        # Any access mode on an unknown resource must FAIL CLOSED
        for mode in ["read", "write", "restart", "status"]:
            res = guard.check_boundary(target, mode)
            assert res.allowed is False, f"Unknown target {target} must be BLOCKED (UNKNOWN = FAIL)"
            assert res.exit_code == ExitCode.SHARED_INFRA_VIOLATION
            assert res.violation_type == "UNKNOWN_INFRASTRUCTURE_RESOURCE"

            with pytest.raises(SharedInfraViolationError) as exc_info:
                verify_infrastructure_boundary(target, mode, guard=guard)
            assert exc_info.value.exit_code == ExitCode.SHARED_INFRA_VIOLATION


# V. Read-only shared infrastructure access permitted
def test_adversarial_V_readonly_shared_infrastructure_access_permitted():
    guard = SharedInfrastructureGuard(
        shared_resources={"shared-postgres", "shared-redis"},
        local_resources={"support_bot"},
    )

    valid_readonly_modes = [
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
    ]

    for mode in valid_readonly_modes:
        res = guard.check_boundary("shared-postgres", mode)
        assert res.allowed is True, f"Mode {mode} should be ALLOWED for readonly_consumer"
        assert res.exit_code == ExitCode.SUCCESS


# Invalid input boundary testing
def test_adversarial_invalid_inputs_fail_closed():
    guard = SharedInfrastructureGuard()

    # Empty resource
    res_empty_res = guard.check_boundary("", "read")
    assert res_empty_res.allowed is False
    assert res_empty_res.exit_code == ExitCode.SHARED_INFRA_VIOLATION

    # Empty mode
    res_empty_mode = guard.check_boundary("shared-postgres", "")
    assert res_empty_mode.allowed is False
    assert res_empty_mode.exit_code == ExitCode.SHARED_INFRA_VIOLATION

    # Malformed / gibberish mode
    res_gibberish = guard.check_boundary("shared-postgres", "gibberish_mode_xyz")
    assert res_gibberish.allowed is False
    assert res_gibberish.exit_code == ExitCode.SHARED_INFRA_VIOLATION
    assert res_gibberish.violation_type == "UNKNOWN_ACCESS_MODE"
