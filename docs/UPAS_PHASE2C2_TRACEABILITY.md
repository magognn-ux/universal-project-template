# UPAS Phase 2C-2 — Security & Concurrency Traceability Matrix

This document establishes formal architectural traceability between the frozen UPAS contracts, the Phase 2C-2 security and concurrency runtime implementations, adversarial threat models, expected failure modes, exit codes, and automated validation tests.

---

## 1. Traceability Mapping Matrix

| Architecture Invariant | Phase 2B Contract | Runtime Enforcement Point | Test Suite | Adversarial Attack Covered | Expected Failure State | Exit Code | Evidence / Result Model |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **Invariant 1: Production Authorization Gate** | `OIDCVerifier`, `OIDCClaims`, `OIDCExpectedConfig` (`contracts/security.py`, `contracts/interfaces.py`) | `GitHubOIDCVerifier` (`upas_core/security/oidc_verifier.py`) | `test_oidc_verifier.py`, `test_adversarial_security.py` | **A.** Unsigned JWT<br>**B.** `alg=none`<br>**C.** Expired JWT<br>**D.** Wrong issuer<br>**E.** Wrong audience<br>**F.** Wrong repository<br>**G.** Wrong environment<br>**H.** Wrong ref<br>**I.** Wrong workflow<br>**J.** Missing required claim<br>**N.** JWKS network failure<br>**O.** Unknown signing key | Fail-Closed Token Validation (`PROD_AUTH_FAILED`) | **43** | `AuthResult(authenticated=False, exit_code=43, error_message=...)` |
| **Invariant 1: Anti-Replay Gate** | `JtiStore` (`contracts/interfaces.py`) | `SQLiteJtiStore` (`upas_core/security/jti_store.py`) | `test_jti_store.py`, `test_adversarial_security.py` | **K.** Malformed JTI<br>**L.** Replayed JTI<br>**M.** Concurrent JTI replay race | Duplicate/Expired JTI Rejection | **43** | `AuthResult(authenticated=False, exit_code=43)` (via HostGuard) |
| **Invariant 1: Host-Side Authorization Guard** | `HostGuard`, `AuthResult` (`contracts/security.py`, `contracts/interfaces.py`) | `ProductionHostGuard` (`upas_core/security/host_guard.py`) | `test_host_guard.py`, `test_adversarial_security.py` | **W.** Local CLI / Developer bypass attempt (empty/dummy tokens, flags) | Production Auth Gate Exception (`ProductionAuthError`) | **43** | `AuthResult(authenticated=False, exit_code=43)` |
| **Invariant 2: Single Active Mutation per Host** | `HostLock`, `LockHandle`, `LockResult` (`contracts/results.py`, `contracts/interfaces.py`) | `AtomicHostLock` (`upas_core/locking/host_lock.py`), `_is_pid_alive_*` | `test_host_lock.py`, `test_adversarial_lock.py` | **P.** Concurrent acquisition race<br>**Q.** Stale lock with dead PID<br>**R.** Active PID reclamation attempt<br>**S.** Lock acquisition timeout exhaustion | Concurrency Mutual Exclusion Blocked | **75** | `LockResult(acquired=False, exit_code=75)` / `ConcurrencyBlockedError` |
| **Invariant 3: Shared Infrastructure Read-Only Boundary** | `InfrastructureGuard`, `GuardResult` (`contracts/results.py`, `contracts/interfaces.py`, `upas.adapter.schema.json`) | `SharedInfrastructureGuard` (`upas_core/governance/infra_guard.py`) | `test_infra_guard.py`, `test_adversarial_infra_guard.py` | **T.** Shared service mutation (restart/stop/recreate/write)<br>**U.** Unknown infrastructure target (`UNKNOWN = FAIL`)<br>**V.** Read-only consumer access | Shared Infrastructure Violation (`SHARED_INFRA_VIOLATION`) | **77** | `GuardResult(allowed=False, exit_code=77)` / `SharedInfraViolationError` |

---

## 2. Component Implementation Details

### 2.1 OIDC Verifier (`upas_core.security.oidc_verifier`)
* **File:** [`upas_core/security/oidc_verifier.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/security/oidc_verifier.py)
* **Cryptographic Engine:** Validates RSA/ECDSA asymmetric signatures against JWKS keys (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`).
* **Strict Alg Enforcement:** Token headers specifying `alg=none`, symmetric HMAC algorithms, or missing `kid` are immediately rejected.
* **Claims Gate:** Enforces expected issuer (`https://token.actions.githubusercontent.com`), expected audience, repository, environment, branch ref, and matching `job_workflow_ref` prefix.
* **Deterministic Outcome:** Fails closed with `ExitCode.PROD_AUTH_FAILED` (43) on signature tampering, expired timestamps, missing claims, or JWKS retrieval errors.

### 2.2 JTI Replay Store (`upas_core.security.jti_store`)
* **File:** [`upas_core/security/jti_store.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/security/jti_store.py)
* **Storage Engine:** SQLite database in Write-Ahead Logging (`WAL`) mode with explicit synchronous transactions and busy timeouts.
* **Atomic Uniqueness:** Relies on primary key uniqueness (`UNIQUE(jti)`) ensuring that under concurrent execution across processes or threads, exactly one attempt succeeds.
* **Expiration Handling:** Tokens with past expiration timestamps are rejected at insertion time; expired records are pruned without compromising active uniqueness.

### 2.3 Host Guard (`upas_core.security.host_guard`)
* **File:** [`upas_core/security/host_guard.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/security/host_guard.py)
* **Final Enforcement Point:** Sits immediately prior to any production mutation pipeline.
* **No Developer Bypass:** CLI flags (`--force`, `--production`, `--approve`) cannot bypass cryptographic OIDC token verification or JTI replay checking.
* **Deterministic Outcome:** Returns structured `AuthResult` with `exit_code=43` or raises `ProductionAuthError`.

### 2.4 Atomic Host Lock (`upas_core.locking.host_lock`)
* **File:** [`upas_core/locking/host_lock.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/locking/host_lock.py)
* **OS-Level Atomic Primitive:** Uses kernel-level atomic file creation (`os.O_CREAT | os.O_EXCL`) rather than racy check-then-create patterns.
* **Metadata Descriptor:** Records owner PID, UTC ISO timestamp, timeout bounds, and host identity.
* **PID Liveness Verification:** Cross-platform verification (`OpenProcess`/`GetExitCodeProcess` on Windows, `os.kill(pid, 0)` with `ESRCH`/`EPERM` discrimination on POSIX).
* **Active vs Stale PID Policy:**
  * If lock owner PID is dead: safely unlinks stale file and atomically reclaims (`stale_reclaimed=True`).
  * If lock owner PID is active: NEVER reclaims; waits until timeout and fails closed with `ExitCode.BLOCKED_CONCURRENCY` (75).
* **Safe Release:** Verifies PID and kernel timestamp match before unlinking.

### 2.5 Shared Infrastructure Guard (`upas_core.governance.infra_guard`)
* **File:** [`upas_core/governance/infra_guard.py`](file:///c:/Users/user/Projects/universal-project-template/upas_core/governance/infra_guard.py)
* **Boundary Enforcement:** Enforces Phase 1 contract rule that external shared infrastructure can only be consumed in read-only mode (`readonly_consumer`).
* **Categorization:**
  * Allowed read-only actions: `read`, `readonly_consumer`, `inspect`, `query`, `status`, `health_check`, `logs`, `ping`.
  * Forbidden mutation actions: `write`, `mutate`, `restart`, `stop`, `remove`, `recreate`, `compose`, `deploy`, `drop`, `alter`.
* **UNKNOWN = FAIL Invariant:** Any unknown resource or unrecognized access mode is blocked with `ExitCode.SHARED_INFRA_VIOLATION` (77).

---

## 3. Adversarial Threat Model Verification Summary

All mandatory adversarial threat scenarios (A through W) were implemented and verified in automated tests:

| Threat Scenario | Description | Test Name | Status |
| :--- | :--- | :--- | :---: |
| **A** | Unsigned JWT | `test_adversarial_A_unsigned_jwt` | **BLOCKED (43)** |
| **B** | `alg=none` JWT | `test_adversarial_B_alg_none` | **BLOCKED (43)** |
| **C** | Expired JWT | `test_adversarial_C_expired_jwt` | **BLOCKED (43)** |
| **D** | Wrong Issuer | `test_adversarial_D_wrong_issuer` | **BLOCKED (43)** |
| **E** | Wrong Audience | `test_adversarial_E_wrong_audience` | **BLOCKED (43)** |
| **F** | Wrong Repository | `test_adversarial_F_wrong_repository` | **BLOCKED (43)** |
| **G** | Wrong Environment | `test_adversarial_G_wrong_environment` | **BLOCKED (43)** |
| **H** | Missing/Empty Ref | `test_adversarial_H_empty_ref` | **BLOCKED (43)** |
| **I** | Wrong Job Workflow Ref | `test_adversarial_I_wrong_workflow` | **BLOCKED (43)** |
| **J** | Missing Required Claim | `test_adversarial_J_missing_claim` | **BLOCKED (43)** |
| **K** | Malformed JTI | `test_adversarial_K_malformed_jti` | **BLOCKED (43)** |
| **L** | Replayed JTI | `test_adversarial_L_replayed_jti` | **BLOCKED (43)** |
| **M** | Concurrent JTI Replay Race | `test_adversarial_M_concurrent_jti_replay` | **BLOCKED (43)** |
| **N** | JWKS Endpoint Network Failure | `test_adversarial_N_jwks_failure` | **BLOCKED (43)** |
| **O** | Unknown Signing Key | `test_adversarial_O_unknown_signing_key` | **BLOCKED (43)** |
| **P** | Concurrent Host Lock Acquisition | `test_adversarial_P_concurrent_acquisition_mutual_exclusion` | **BLOCKED (75)** |
| **Q** | Stale Lock with Dead PID | `test_adversarial_Q_stale_lock_with_dead_pid_is_reclaimed` | **RECLAIMED (0)** |
| **R** | Active PID Reclamation Attempt | `test_adversarial_R_active_pid_must_never_be_reclaimed` | **BLOCKED (75)** |
| **S** | Lock Timeout Exhaustion | `test_adversarial_S_lock_timeout_exhaustion` | **BLOCKED (75)** |
| **T** | Shared Infrastructure Mutation | `test_adversarial_T_shared_infrastructure_mutation_attempts_blocked` | **BLOCKED (77)** |
| **U** | Unknown Infrastructure Target (`UNKNOWN = FAIL`) | `test_adversarial_U_unknown_infrastructure_target_fails_closed` | **BLOCKED (77)** |
| **V** | Read-Only Shared Infrastructure Access | `test_adversarial_V_readonly_shared_infrastructure_access_permitted` | **ALLOWED (0)** |
| **W** | Developer / Local Bypass Attempt | `test_adversarial_W_developer_bypass_attempt` | **BLOCKED (43)** |
