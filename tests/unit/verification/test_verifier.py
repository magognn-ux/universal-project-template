"""
Unit tests for UPAS Post-Deploy Verifier.
Tests container identity checking, running digest verification, health check and smoke test evaluation.
"""

import sys
from upas_core.contracts.enums import ExitCode
from upas_core.verification.verifier import (
    PostDeployVerifier,
    verify_post_deploy_state,
)

_VALID_DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def test_post_deploy_verifier_all_pass():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        expected_container_name="support_bot_app",
        actual_container_name="support_bot_app",
        smoke_test_spec={"command": f"{sys.executable} -c 'pass'"},
    )
    assert res.verified is True
    assert res.exit_code == ExitCode.SUCCESS
    assert res.identity_matched is True
    assert res.smoke_test_passed is True


def test_post_deploy_verifier_container_identity_mismatch():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        expected_container_name="support_bot_app",
        actual_container_name="wrong_container_app",
    )
    assert res.verified is False
    assert res.identity_matched is False
    assert "identity mismatch" in res.error_message


def test_post_deploy_verifier_running_digest_mismatch():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    assert res.verified is False
    assert res.exit_code == ExitCode.DIGEST_MISMATCH
    assert "digest mismatch" in res.error_message


def test_post_deploy_verifier_smoke_test_failure():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        smoke_test_spec={"command": f"{sys.executable} -c 'import sys; sys.exit(1)'"},
    )
    assert res.verified is False
    assert res.smoke_test_passed is False
    assert res.exit_code == ExitCode.TESTS_FAILED


def test_post_deploy_verifier_unknown_health_check_type_fails_closed():
    """Regression test for UPAS-V101-01: unknown health check type must fail closed."""
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        health_check_spec={"type": "unknown_future_probe", "timeout_seconds": 5},
    )
    assert res.verified is False
    assert res.health_check_passed is False
    assert res.smoke_test_passed is False
    assert res.exit_code == ExitCode.TESTS_FAILED
    assert "Unsupported health check type 'unknown_future_probe'" in res.error_message


def test_post_deploy_verifier_unsupported_tcp_socket_fails_closed():
    """Verify currently unimplemented schema types fail closed instead of silently passing."""
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        health_check_spec={"type": "tcp_socket", "port": 8080},
    )
    assert res.verified is False
    assert res.health_check_passed is False
    assert res.smoke_test_passed is False
    assert res.exit_code == ExitCode.TESTS_FAILED
    assert "Unsupported health check type 'tcp_socket'" in res.error_message


def test_post_deploy_verifier_custom_command_health_check_pass():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        health_check_spec={"type": "custom_command", "command": f"{sys.executable} -c 'pass'"},
    )
    assert res.verified is True
    assert res.health_check_passed is True
    assert res.exit_code == ExitCode.SUCCESS


def test_post_deploy_verifier_custom_command_health_check_failure():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        health_check_spec={"type": "custom_command", "command": f"{sys.executable} -c 'import sys; sys.exit(2)'"},
    )
    assert res.verified is False
    assert res.health_check_passed is False
    assert res.exit_code == ExitCode.TESTS_FAILED
    assert "Custom health check command failed" in res.error_message


def test_post_deploy_verifier_process_check_pass():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        health_check_spec={"type": "process_check", "command": f"{sys.executable} -c 'pass'"},
    )
    assert res.verified is True
    assert res.health_check_passed is True
    assert res.exit_code == ExitCode.SUCCESS


def test_post_deploy_verifier_process_check_failure():
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        health_check_spec={"type": "process_check", "command": f"{sys.executable} -c 'import sys; sys.exit(3)'"},
    )
    assert res.verified is False
    assert res.health_check_passed is False
    assert res.exit_code == ExitCode.TESTS_FAILED
    assert "Custom health check command failed" in res.error_message


def test_post_deploy_verifier_http_get_failure(monkeypatch):
    """Test HTTP health check failure on bad endpoint."""
    verifier = PostDeployVerifier()
    res = verifier.verify_runtime(
        service_name="support_bot",
        approved_digest=_VALID_DIGEST,
        running_digest=_VALID_DIGEST,
        health_check_spec={
            "type": "http_get",
            "endpoint": "http://127.0.0.1:59999/nonexistent",
            "timeout_seconds": 1,
            "max_retries": 1,
            "retry_interval_seconds": 0,
        },
    )
    assert res.verified is False
    assert res.health_check_passed is False
    assert res.exit_code == ExitCode.TESTS_FAILED
    assert "Health check failed" in res.error_message

