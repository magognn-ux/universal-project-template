"""
Unit tests for UPAS GitHub OIDC Verifier.
Verifies cryptographic validation, claim checking, and fail-closed security.
"""

import time
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from upas_core.contracts.enums import AuthPolicy, ExitCode
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.security.oidc_verifier import GitHubOIDCVerifier, verify_oidc_token


@pytest.fixture
def rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def standard_oidc_config():
    return OIDCExpectedConfig(
        expected_issuer="https://token.actions.githubusercontent.com",
        expected_audience="upas-production-gate",
        expected_repository="octocat/hello-world",
        expected_environment="production",
        required_claims=["repository", "environment", "ref", "job_workflow_ref"],
    )


def make_valid_payload():
    now = int(time.time())
    return {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "upas-production-gate",
        "repository": "octocat/hello-world",
        "environment": "production",
        "ref": "refs/heads/main",
        "job_workflow_ref": "octocat/hello-world/.github/workflows/deploy.yml@refs/heads/main",
        "jti": "550e8400-e29b-41d4-a716-446655440000",
        "exp": now + 3600,
        "sub": "repo:octocat/hello-world:environment:production",
        "run_id": "12345678",
        "actor": "octocat",
    }


def test_valid_oidc_token_passes(rsa_keypair, standard_oidc_config):
    private_key, public_key = rsa_keypair
    payload = make_valid_payload()
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "key-1"})

    verifier = GitHubOIDCVerifier(signing_keys={"key-1": public_key})
    result = verifier.verify_token(token, standard_oidc_config)

    assert result.authenticated is True
    assert result.exit_code == ExitCode.SUCCESS
    assert result.policy == AuthPolicy.GITHUB_ENVIRONMENT_OIDC
    assert result.actor == "octocat"
    assert result.run_id == "12345678"
    assert result.environment == "production"
    assert result.claims is not None
    assert result.claims.jti == "550e8400-e29b-41d4-a716-446655440000"


def test_empty_or_malformed_token_fails_closed(standard_oidc_config):
    verifier = GitHubOIDCVerifier()
    res1 = verifier.verify_token("", standard_oidc_config)
    assert res1.authenticated is False
    assert res1.exit_code == ExitCode.PROD_AUTH_FAILED

    res2 = verifier.verify_token("invalid.jwt.token", standard_oidc_config)
    assert res2.authenticated is False
    assert res2.exit_code == ExitCode.PROD_AUTH_FAILED


def test_missing_signing_key_fails_closed(rsa_keypair, standard_oidc_config):
    private_key, _ = rsa_keypair
    payload = make_valid_payload()
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "unknown-kid"})

    verifier = GitHubOIDCVerifier(signing_keys={})
    result = verifier.verify_token(token, standard_oidc_config)
    assert result.authenticated is False
    assert result.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "JWKS key retrieval failed" in result.error_message


def test_tampered_token_signature_fails_closed(rsa_keypair, standard_oidc_config):
    private_key, public_key = rsa_keypair
    payload = make_valid_payload()
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "key-1"})

    # Tamper with token payload portion
    parts = token.split(".")
    tampered_token = f"{parts[0]}.eyJyZXBvIjoiZmFrZSJ9.{parts[2]}"

    verifier = GitHubOIDCVerifier(signing_keys={"key-1": public_key})
    result = verifier.verify_token(tampered_token, standard_oidc_config)
    assert result.authenticated is False
    assert result.exit_code == ExitCode.PROD_AUTH_FAILED


def test_convenience_verify_oidc_token(rsa_keypair, standard_oidc_config):
    private_key, public_key = rsa_keypair
    payload = make_valid_payload()
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "key-1"})
    verifier = GitHubOIDCVerifier(signing_keys={"key-1": public_key})

    result = verify_oidc_token(token, standard_oidc_config, verifier=verifier)
    assert result.authenticated is True
