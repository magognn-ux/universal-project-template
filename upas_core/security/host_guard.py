"""
UPAS Host-Side Production Authorization Guard.
Implements the HostGuard protocol.
Enforces Invariant 1: Production Authorization Gate (Fail-Closed Exit Code 43).
"""

from typing import Optional
from upas_core.contracts.enums import AuthPolicy, ExitCode
from upas_core.contracts.errors import ProductionAuthError
from upas_core.contracts.interfaces import HostGuard, JtiStore, OIDCVerifier
from upas_core.contracts.security import AuthResult, OIDCExpectedConfig
from upas_core.security.jti_store import SQLiteJtiStore
from upas_core.security.oidc_verifier import GitHubOIDCVerifier


class ProductionHostGuard(HostGuard):
    """
    Host-side authorization gate enforcing that production mutations only execute
    with a cryptographically valid, un-replayed GitHub Actions OIDC token.
    Local developer CLI flags (--force, --approve, etc.) cannot bypass this guard.
    """

    def __init__(
        self,
        verifier: Optional[OIDCVerifier] = None,
        jti_store: Optional[JtiStore] = None,
    ):
        self.verifier = verifier or GitHubOIDCVerifier()
        self.jti_store = jti_store or SQLiteJtiStore()

    def authorize_production_mutation(
        self,
        token: str,
        config: OIDCExpectedConfig,
    ) -> AuthResult:
        """
        Evaluates whether a production mutation is authorized.
        Validates OIDC JWT signature, claims, and enforces atomic JTI replay prevention.
        Returns AuthResult with ExitCode.PROD_AUTH_FAILED (43) on any authorization failure.
        """
        target_env = config.expected_environment if config else "unknown"

        # 1. Reject missing or malformed inputs
        if not token or not isinstance(token, str) or not token.strip():
            return AuthResult(
                authenticated=False,
                policy=AuthPolicy.GITHUB_ENVIRONMENT_OIDC,
                actor="unknown",
                run_id="unknown",
                environment=target_env,
                approval_timestamp="",
                error_message="Production mutation rejected: missing or empty OIDC authorization token",
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
                error_message="Production mutation rejected: missing or invalid OIDC expected config",
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # 2. Cryptographic and claim verification
        auth_result = self.verifier.verify_token(token, config)
        if not auth_result.authenticated or not auth_result.claims:
            return auth_result

        claims = auth_result.claims

        # 3. Enforce single-use JTI replay protection
        jti = claims.jti
        exp = claims.exp

        is_recorded = self.jti_store.record_jti(jti, exp)
        if not is_recorded:
            return AuthResult(
                authenticated=False,
                policy=auth_result.policy,
                actor=auth_result.actor,
                run_id=auth_result.run_id,
                environment=auth_result.environment,
                approval_timestamp="",
                claims=None,
                error_message=(
                    f"Production mutation rejected: JTI replay detected or token expired (jti='{jti}')"
                ),
                exit_code=ExitCode.PROD_AUTH_FAILED,
            )

        # 4. Successfully authorized
        return auth_result


def verify_production_authorization(
    token: str,
    config: OIDCExpectedConfig,
    guard: Optional[HostGuard] = None,
) -> AuthResult:
    """
    Fail-closed gate function for production mutation authorization.
    Raises ProductionAuthError (exit code 43) if authorization fails.
    """
    guard = guard or ProductionHostGuard()
    result = guard.authorize_production_mutation(token, config)
    if not result.authenticated:
        raise ProductionAuthError(result.error_message or "Production authorization failed")
    return result
