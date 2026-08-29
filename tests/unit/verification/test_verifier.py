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
