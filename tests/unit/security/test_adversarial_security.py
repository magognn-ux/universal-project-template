"""
Adversarial Security Tests for UPAS OIDC & Host Guard.
Covers threat models A-O and W:
  A. Unsigned JWT
  B. alg=none JWT
  C. Expired JWT
  D. Wrong issuer
  E. Wrong audience
  F. Wrong repository
  G. Wrong environment
  H. Wrong ref
  I. Wrong workflow
  J. Missing required claim
  K. Malformed JTI
  L. Replayed JTI
  M. Concurrent JTI replay
  N. JWKS failure
  O. Unknown signing key
  W. Local / developer bypass attempt
"""

import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.security import OIDCExpectedConfig
from upas_core.security.host_guard import ProductionHostGuard
from upas_core.security.jti_store import SQLiteJtiStore
from upas_core.security.oidc_verifier import GitHubOIDCVerifier


@pytest.fixture
def rsa_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def base_config():
    return OIDCExpectedConfig(
        expected_issuer="https://token.actions.githubusercontent.com",
        expected_audience="upas-production-gate",
        expected_repository="octocat/hello-world",
        expected_environment="production",
        required_claims=["repository", "environment", "ref", "job_workflow_ref"],
    )


def build_payload(overrides=None):
    now = int(time.time())
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "upas-production-gate",
        "repository": "octocat/hello-world",
        "environment": "production",
        "ref": "refs/heads/main",
        "job_workflow_ref": "octocat/hello-world/.github/workflows/deploy.yml@refs/heads/main",
        "jti": f"adv-jti-{now}-{time.monotonic_ns()}",
        "exp": now + 3600,
        "actor": "octocat",
        "run_id": "112233",
    }
    if overrides:
        payload.update(overrides)
    return payload


# A. Unsigned JWT
def test_adversarial_A_unsigned_jwt(base_config):
    verifier = GitHubOIDCVerifier()
    # Unsigned token (missing third component)
    raw_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJzdWIiOiIxIn0."
    res = verifier.verify_token(raw_token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED


# B. alg=none JWT
def test_adversarial_B_alg_none(base_config):
    verifier = GitHubOIDCVerifier()
    # Token crafted with alg=none
    none_token = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwiYXVkIjoidXB"
        "hcy1wcm9kdWN0aW9uLWdhdGUiLCJyZXBvc2l0b3J5Ijoib2N0b2NhdC9oZWxsby13b3JsZCIsImVudmlyb2"
        "5tZW50IjoicHJvZHVjdGlvbiIsInJlZiI6InJlZnMvaGVhZHMvbWFpbiIsImpvYl93b3JrZmxvd19yZWYiO"
        "iJvY3RvY2F0L2hlbGxvLXdvcmxkLy5naXRodWIvd29ya2Zsb3dzL2RlcGxveS55bWxAcmVmcy9oZWFkcy9t"
        "YWluIiwianRpIjoiYWR2LW5vbmUiLCJleHAiOjIwMDAwMDAwMDB9."
    )
    res = verifier.verify_token(none_token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "Forbidden or insecure JWT algorithm" in res.error_message


# C. Expired JWT
def test_adversarial_C_expired_jwt(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({"exp": int(time.time()) - 100})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "expired" in res.error_message.lower()


# D. Wrong Issuer
def test_adversarial_D_wrong_issuer(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({"iss": "https://evil-issuer.com"})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED


# E. Wrong Audience
def test_adversarial_E_wrong_audience(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({"aud": "wrong-audience"})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED


# F. Wrong Repository
def test_adversarial_F_wrong_repository(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({"repository": "attacker/malicious-repo"})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "repository mismatch" in res.error_message


# G. Wrong Environment
def test_adversarial_G_wrong_environment(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({"environment": "staging"})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "environment mismatch" in res.error_message


# H. Wrong Ref
def test_adversarial_H_empty_ref(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({"ref": ""})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED


# I. Wrong Workflow & Hardened Job Workflow Ref Attacks
def test_adversarial_I_wrong_workflow(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({
        "job_workflow_ref": "attacker-org/foreign-repo/.github/workflows/evil.yml@refs/heads/main"
    })
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "does not originate from" in res.error_message


@pytest.mark.parametrize(
    "malicious_workflow_ref",
    [
        "attacker/universal-project-template/.github/workflows/upas-pipeline.yml@refs/tags/v1.0.0",
        "magognn-ux/universal-project-template-fork/.github/workflows/upas-pipeline.yml@refs/tags/v1.0.0",
        "evil-org/universal-project-template/.github/workflows/upas-pipeline.yml@refs/tags/v1.0.0",
        "some-org/evil-universal-project-template/.github/workflows/upas-pipeline.yml@refs/heads/main",
    ],
)
def test_adversarial_I_job_workflow_ref_substring_and_fork_rejected(rsa_keys, base_config, malicious_workflow_ref):
    priv, pub = rsa_keys
    payload = build_payload({"job_workflow_ref": malicious_workflow_ref})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "does not originate from" in res.error_message


def test_adversarial_I_trusted_central_upas_workflow_accepted(rsa_keys):
    priv, pub = rsa_keys
    pilot_config = OIDCExpectedConfig(
        expected_issuer="https://token.actions.githubusercontent.com",
        expected_audience="upas-production-gate",
        expected_repository="magognn-ux/support-bot",
        expected_environment="production",
        required_claims=["repository", "environment", "ref", "job_workflow_ref"],
    )
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "upas-production-gate",
        "repository": "magognn-ux/support-bot",
        "environment": "production",
        "ref": "refs/tags/v0.4.0",
        "job_workflow_ref": "magognn-ux/universal-project-template/.github/workflows/upas-pipeline.yml@refs/tags/v1.0.1",
        "jti": f"trusted-upas-{time.time()}",
        "exp": int(time.time()) + 3600,
        "actor": "release-manager",
        "run_id": "998877",
    }
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})
    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, pilot_config)
    assert res.authenticated is True
    assert res.exit_code == ExitCode.SUCCESS


# J. Missing Required Claim
def test_adversarial_J_missing_claim(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload()
    del payload["repository"]  # remove required claim
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED


# K. Malformed JTI
def test_adversarial_K_malformed_jti(rsa_keys, base_config):
    priv, pub = rsa_keys
    payload = build_payload({"jti": ""})
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k1"})

    verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED


# L. Replayed JTI
def test_adversarial_L_replayed_jti(rsa_keys, base_config):
    priv, pub = rsa_keys
    with tempfile.TemporaryDirectory() as tmpdir:
        store = SQLiteJtiStore(os.path.join(tmpdir, "jti.db"))
        verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})
        guard = ProductionHostGuard(verifier=verifier, jti_store=store)

        token = jwt.encode(build_payload({"jti": "jti-single-use-123"}), priv, algorithm="RS256", headers={"kid": "k1"})

        # First use: passes
        res1 = guard.authorize_production_mutation(token, base_config)
        assert res1.authenticated is True

        # Replay attack: blocked
        res2 = guard.authorize_production_mutation(token, base_config)
        assert res2.authenticated is False
        assert res2.exit_code == ExitCode.PROD_AUTH_FAILED
        assert "replay detected" in res2.error_message


# M. Concurrent JTI Replay
def test_adversarial_M_concurrent_jti_replay(rsa_keys, base_config):
    priv, pub = rsa_keys
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "concurrent_jti.db")
        verifier = GitHubOIDCVerifier(signing_keys={"k1": pub})

        token = jwt.encode(build_payload({"jti": "race-jti-target"}), priv, algorithm="RS256", headers={"kid": "k1"})

        def attempt_auth():
            local_store = SQLiteJtiStore(db_path)
            local_guard = ProductionHostGuard(verifier=verifier, jti_store=local_store)
            return local_guard.authorize_production_mutation(token, base_config)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(attempt_auth) for _ in range(16)]
            results = [f.result() for f in futures]

        successes = [r for r in results if r.authenticated]
        failures = [r for r in results if not r.authenticated]

        # Exactly 1 success, 15 failures
        assert len(successes) == 1
        assert len(failures) == 15
        assert all(f.exit_code == ExitCode.PROD_AUTH_FAILED for f in failures)


# N. JWKS Failure / Network Error
def test_adversarial_N_jwks_failure(rsa_keys, base_config):
    priv, _ = rsa_keys
    payload = build_payload()
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "k-invalid-url"})

    # Point to an invalid unreachable JWKS endpoint
    verifier = GitHubOIDCVerifier(jwks_url="http://127.0.0.1:54321/unreachable/jwks")
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED
    assert "JWKS key retrieval failed" in res.error_message


# O. Unknown Signing Key
def test_adversarial_O_unknown_signing_key(rsa_keys, base_config):
    priv, _ = rsa_keys
    payload = build_payload()
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "unregistered-key"})

    # Verifier only knows about 'known-key'
    _, pub_known = rsa_keys
    verifier = GitHubOIDCVerifier(signing_keys={"known-key": pub_known})
    res = verifier.verify_token(token, base_config)
    assert res.authenticated is False
    assert res.exit_code == ExitCode.PROD_AUTH_FAILED


# W. Developer / Local Bypass Attempt
def test_adversarial_W_developer_bypass_attempt(base_config):
    with tempfile.TemporaryDirectory() as tmpdir:
        guard = ProductionHostGuard(jti_store=SQLiteJtiStore(os.path.join(tmpdir, "jti.db")))

        # Attacker tries empty token
        res1 = guard.authorize_production_mutation("", base_config)
        assert res1.authenticated is False
        assert res1.exit_code == ExitCode.PROD_AUTH_FAILED

        # Attacker tries dummy token
        res2 = guard.authorize_production_mutation("Bearer admin-token-override", base_config)
        assert res2.authenticated is False
        assert res2.exit_code == ExitCode.PROD_AUTH_FAILED
