"""
Unit tests for UPAS Host Guard.
Tests host authorization enforcement, JTI replay integration, and fail-closed gates.
"""

import os
import tempfile
import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import ProductionAuthError
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.security.host_guard import ProductionHostGuard, verify_production_authorization
from upas_core.security.jti_store import SQLiteJtiStore
from upas_core.security.oidc_verifier import GitHubOIDCVerifier


@pytest.fixture
def test_setup():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "guard_jti.db")
        jti_store = SQLiteJtiStore(db_path)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        verifier = GitHubOIDCVerifier(signing_keys={"guard-key": public_key})
        guard = ProductionHostGuard(verifier=verifier, jti_store=jti_store)

        config = OIDCExpectedConfig(
            expected_issuer="https://token.actions.githubusercontent.com",
            expected_audience="upas-production-gate",
            expected_repository="octocat/hello-world",
            expected_environment="production",
            required_claims=["repository", "environment", "ref", "job_workflow_ref"],
        )

        yield guard, private_key, config


def make_valid_token(private_key, jti="guard-jti-001"):
    now = int(time.time())
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "upas-production-gate",
        "repository": "octocat/hello-world",
        "environment": "production",
        "ref": "refs/heads/main",
        "job_workflow_ref": "octocat/hello-world/.github/workflows/deploy.yml@refs/heads/main",
        "jti": jti,
        "exp": now + 3600,
        "actor": "octocat",
        "run_id": "987654",
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "guard-key"})


def test_host_guard_first_authorization_succeeds(test_setup):
    guard, private_key, config = test_setup
    token = make_valid_token(private_key, jti="auth-jti-100")

    result = guard.authorize_production_mutation(token, config)
    assert result.authenticated is True
    assert result.exit_code == ExitCode.SUCCESS
    assert result.actor == "octocat"
    assert result.run_id == "987654"


def test_host_guard_jti_replay_fails_closed(test_setup):
    guard, private_key, config = test_setup
    token = make_valid_token(private_key, jti="auth-jti-replay")

    # First attempt: succeeds
    res1 = guard.authorize_production_mutation(token, config)
    assert res1.authenticated is True

    # Second attempt with same token/JTI: must fail closed with exit code 43
    res2 = guard.authorize_production_mutation(token, config)
    assert res2.authenticated is False
    assert res2.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "JTI replay detected" in res2.error_message


def test_verify_production_authorization_raises_exception_on_failure(test_setup):
    guard, private_key, config = test_setup
    token = make_valid_token(private_key, jti="auth-jti-exc")

    # First succeeds
    res = verify_production_authorization(token, config, guard=guard)
    assert res.authenticated is True

    # Replay raises ProductionAuthError (exit code 43)
    with pytest.raises(ProductionAuthError) as exc_info:
        verify_production_authorization(token, config, guard=guard)
    assert exc_info.value.exit_code == ExitCode.PROD_AUTH_FAILED
