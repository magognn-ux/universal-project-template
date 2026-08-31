"""
UPAS OIDC JWT Verification Engine.
Implements the OIDCVerifier protocol for GitHub Actions OIDC tokens.
Enforces Invariant 1: Production Authorization Gate.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    PyJWTError,
)

from upas_core.contracts.enums import AuthPolicy, ExitCode
from upas_core.contracts.interfaces import OIDCVerifier
from upas_core.contracts.security import AuthResult, OIDCClaims, OIDCExpectedConfig

_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


class GitHubOIDCVerifier(OIDCVerifier):
    """
    Cryptographic verifier for GitHub Actions OIDC JWTs.
    Validates signature via JWKS, algorithm safety, token expiration,
    and strict claim alignment with upas.adapter.yaml configuration.
    """

    def __init__(
        self,
        jwks_url: str = "https://token.actions.githubusercontent.com/.well-known/jwks",
        jwks_client: Optional[Any] = None,
        signing_keys: Optional[Dict[str, Any]] = None,
        jwks_cache_ttl_seconds: int = 3600,
    ):
        self.jwks_url = jwks_url
        self.signing_keys = signing_keys or {}
        self.jwks_cache_ttl_seconds = jwks_cache_ttl_seconds
        self._jwks_client = jwks_client

    def _get_jwks_client(self) -> jwt.PyJWKClient:
        if self._jwks_client is None:
            self._jwks_client = jwt.PyJWKClient(
                self.jwks_url,
                cache_jwk_set=True,
                lifespan=self.jwks_cache_ttl_seconds,
            )
        return self._jwks_client

    def _get_signing_key(self, token: str, kid: Optional[str]) -> Any:
        """
        Resolves the public signing key matching the token's 'kid' header.
        Fails closed if the key is unknown or cannot be fetched.
        """
        if kid and kid in self.signing_keys:
            return self.signing_keys[kid]

        if not kid:
            raise ValueError("OIDC token header missing 'kid' claim")

        try:
            jwks_client = self._get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            return signing_key.key
        except Exception as exc:
            raise ValueError(f"Failed to resolve JWKS signing key for kid '{kid}': {exc}") from exc

    def verify_token(self, token: str, config: OIDCExpectedConfig) -> AuthResult:
        """
        Cryptographically verifies the given OIDC JWT token against JWKS and config.
        Fails closed with ExitCode.PROD_AUTH_FAILED on any mismatch or error.
        """
        target_env = config.expected_environment if config else "unknown"

        if not token or not isinstance(token, str) or not token.strip():
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message="OIDC token is missing or empty",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        if not config or not isinstance(config, OIDCExpectedConfig):
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message="Invalid or missing OIDC expected configuration",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # 1. Inspect unverified header for algorithm safety and key identification
        try:
            unverified_header = jwt.get_unverified_header(token)
        except Exception as exc:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message=f"Malformed JWT header: {exc}",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        alg = unverified_header.get("alg")
        if not alg or alg.lower() == "none" or alg not in _ALLOWED_ALGORITHMS:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message=f"Forbidden or insecure JWT algorithm: '{alg}' (must be one of {_ALLOWED_ALGORITHMS})",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        kid = unverified_header.get("kid")
        if not kid:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message="JWT header is missing 'kid' (Key ID)",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # 2. Retrieve public key
        try:
            signing_key = self._get_signing_key(token, kid)
        except Exception as exc:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message=f"JWKS key retrieval failed: {exc}",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # 3. Cryptographically decode and verify claims
        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=[alg],
                audience=config.expected_audience,
                issuer=config.expected_issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": ["exp", "iss", "aud", "jti"],
                },
            )
        except ExpiredSignatureError:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message="OIDC token has expired (exp claim violation)",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )
        except InvalidIssuerError as exc:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message=f"OIDC token issuer mismatch: {exc}",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )
        except InvalidAudienceError as exc:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message=f"OIDC token audience mismatch: {exc}",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )
        except InvalidSignatureError as exc:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message=f"OIDC token signature verification failed: {exc}",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )
        except PyJWTError as exc:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message=f"OIDC token validation error: {exc}",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # 4. Enforce strict repository, environment, and required claims matching
        actual_repo = payload.get("repository")
        if actual_repo != config.expected_repository:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor=str(payload.get("actor", "unknown")),
                run_id=str(payload.get("run_id", "unknown")),
                environment=target_env,
                approval_timestamp="",
                error_message=f"OIDC repository mismatch: expected '{config.expected_repository}', got '{actual_repo}'",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        actual_env = payload.get("environment")
        if actual_env != config.expected_environment:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor=str(payload.get("actor", "unknown")),
                run_id=str(payload.get("run_id", "unknown")),
                environment=str(actual_env),
                approval_timestamp="",
                error_message=f"OIDC environment mismatch: expected '{config.expected_environment}', got '{actual_env}'",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # Verify all configured required claims are present and non-empty
        for req_claim in config.required_claims:
            val = payload.get(req_claim)
            if val is None or (isinstance(val, str) and not val.strip()):
                return AuthResult(
                    authenticated=False,
                    policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                    actor=str(payload.get("actor", "unknown")),
                    run_id=str(payload.get("run_id", "unknown")),
                    environment=actual_env or target_env,
                    approval_timestamp="",
                    error_message=f"OIDC token missing mandatory claim '{req_claim}'",
                    exit_code=ExitCode.PROD_AUTH_FAILED,
                )

        ref = payload.get("ref")
        job_workflow_ref = payload.get("job_workflow_ref")
        if not ref or not isinstance(ref, str) or not ref.strip():
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor=str(payload.get("actor", "unknown")),
                run_id=str(payload.get("run_id", "unknown")),
                environment=actual_env or target_env,
                approval_timestamp="",
                error_message="OIDC token missing or empty 'ref' claim",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        if not job_workflow_ref or not isinstance(job_workflow_ref, str) or not job_workflow_ref.strip():
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor=str(payload.get("actor", "unknown")),
                run_id=str(payload.get("run_id", "unknown")),
                environment=actual_env or target_env,
                approval_timestamp="",
                error_message="OIDC token missing or empty 'job_workflow_ref' claim",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # Ensure job_workflow_ref originates from expected repository or trusted UPAS reusable template
        expected_owner = config.expected_repository.split("/")[0] if "/" in config.expected_repository else config.expected_repository
        is_direct_repo = job_workflow_ref.startswith(f"{config.expected_repository}/")
        is_trusted_template = (
            job_workflow_ref.startswith("magognn-ux/universal-project-template/") or
            job_workflow_ref.startswith(f"{expected_owner}/universal-project-template/")
        )
        if not (is_direct_repo or is_trusted_template):
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor=str(payload.get("actor", "unknown")),
                run_id=str(payload.get("run_id", "unknown")),
                environment=actual_env or target_env,
                approval_timestamp="",
                error_message=f"OIDC job_workflow_ref '{job_workflow_ref}' does not originate from '{config.expected_repository}' or trusted template",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # 5. Build validated claims model
        try:
            claims_model = OIDCClaims(
                iss=payload["iss"],
                aud=payload["aud"],
                repository=payload["repository"],
                environment=payload["environment"],
                ref=payload["ref"],
                job_workflow_ref=payload["job_workflow_ref"],
                jti=payload["jti"],
                exp=int(payload["exp"]),
                sub=payload.get("sub"),
                run_id=str(payload["run_id"]) if payload.get("run_id") is not None else None,
                actor=payload.get("actor"),
            )
        except Exception as exc:
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor=str(payload.get("actor", "unknown")),
                run_id=str(payload.get("run_id", "unknown")),
                environment=actual_env or target_env,
                approval_timestamp="",
                error_message=f"Failed to construct validated claims model: {exc}",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        return AuthResult(
            authenticated=True,
            policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
            actor=claims_model.actor or "unknown",
            run_id=claims_model.run_id or "unknown",
            environment=claims_model.environment,
            approval_timestamp=now_iso,
            claims=claims_model,
            exit_code=ExitCode.SUCCESS,
        )


def verify_oidc_token(
    token: str,
    config: OIDCExpectedConfig,
    verifier: Optional[OIDCVerifier] = None,
) -> AuthResult:
    """Convenience functional interface for OIDC verification."""
    verifier = verifier or GitHubOIDCVerifier()
    return verifier.verify_token(token, config)
