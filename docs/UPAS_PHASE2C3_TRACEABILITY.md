# UPAS Phase 2C-3 — Deployment & Verification Primitives Traceability Matrix

This document establishes formal architectural traceability between the frozen UPAS contracts, the Phase 2C-3 deployment, backup, and verification primitives, lifecycle state transitions, adversarial threat models, and automated tests.

---

## 1. Traceability Mapping Matrix

| Architectural Requirement | Phase 2B Contract | Runtime Implementation | Primary Failure Mode | Exit Code | Automated Test Suites |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Invariant 1: Digest Integrity** | `ArtifactVerifier`, `ArtifactDescriptor`, `ArtifactVerificationResult` | `CanonicalArtifactVerifier` (`upas_core/deployment/artifact_verifier.py`) | `DIGEST_MISMATCH` | **65** | `test_artifact_verifier.py`, `test_adversarial_deployment.py` |
| **Invariant 2: Backup Gate** | `CommandRunner`, `CommandSpec`, `ExecutionResult` | `PreDeployBackupManager`, `BackupRecord` (`upas_core/backup/backup_manager.py`) | `FAILED_BACKUP` | **78** | `test_backup_manager.py`, `test_adversarial_deployment.py` |
| **Invariant 3: Migration Safety** | `MigrationOrchestrator`, `MigrationSpec`, `MigrationResult` | `SafeMigrationRunner` (`upas_core/deployment/migration_runner.py`) | `MIGRATION_FAILED` | **70** | `test_migration_runner.py`, `test_adversarial_deployment.py` |
| **Invariant 4: Safe Rollback vs EMERGENCY_HALT** | `RollbackSafetyArbiter`, `RollbackDecision` | `DefaultRollbackSafetyArbiter` (`upas_core/deployment/rollback_arbiter.py`) | `EMERGENCY_HALT` | **81** | `test_rollback_arbiter.py`, `test_adversarial_deployment.py` |
| **Invariant 5: Multi-Dimensional Verification** | `ArtifactVerifier`, `CommandRunner` | `PostDeployVerifier`, `RuntimeStateResult` (`upas_core/verification/verifier.py`) | `TESTS_FAILED` / `DIGEST_MISMATCH` | **1** / **65** | `test_verifier.py`, `test_deployer_pipeline.py` |
| **Invariant 6: Unknown Remote State Boundary** | `ExecutionResult`, `DeploymentLifecycleStateMachine` | `ProductionDeployer` (`upas_core/deployment/deployer.py`) | `UNKNOWN_REMOTE_STATE` | **125** | `test_adversarial_deployment.py` |
| **Invariant 7: Immutable Pull by Digest** | `ArtifactDescriptor`, `ArtifactVerifier` | `ProductionDeployer` (`upas_core/deployment/deployer.py`) | `FAILED_PULL` | **66** | `test_adversarial_deployment.py` |

---

## 2. Deployment Lifecycle State Transitions

The deployment pipeline primitive strictly enforces the following ordered sequence via `DeploymentLifecycleStateMachine`:

```text
PROD_APPROVAL_PENDING
       ↓ (HostGuard OIDC token & JTI freshness)
 PROD_AUTHORIZED
       ↓ (AtomicHostLock acquisition)
  LOCK_ACQUIRED
       ↓ (ResourcePreflight inspection)
    PREFLIGHT
       ↓ (PreDeployBackupManager execution & checksum)
PRE_DEPLOY_BACKUP
       ↓ (SafeMigrationRunner pre-deploy hook)
    MIGRATION
       ↓ (Pull exact immutable digest & verify digest)
 PULL_BY_DIGEST
       ↓ (Safe service restart)
     RESTART
       ↓ (PostDeployVerifier identity, digest, health, smoke)
POST_DEPLOY_VERIFY
       ↓ (All verification checks pass)
DEPLOYMENT_VERIFIED
```

### Failure & Rollback Transitions:
1. **Additive Schema Migration Failure:**
   `POST_DEPLOY_VERIFY -> AUTO_ROLLBACK -> ROLLED_BACK` (Safe application rollback permitted).
2. **Non-Additive Schema Migration Failure:**
   `POST_DEPLOY_VERIFY -> EMERGENCY_HALT` (Automated application rollback blocked to prevent schema corruption; human DB restore decision required).
3. **Remote Connection Dropped During Mutation:**
   `RESTART -> UNKNOWN_REMOTE_STATE` (Exit 125, immediate halt, no destructive blind retry).

---

## 3. Adversarial Threat Model Verification

All Phase 2C-3 adversarial scenarios were implemented and verified in automated suites:

| Adversarial Attack / Threat Scenario | Target Behavior | Test Name | Result |
| :--- | :--- | :--- | :---: |
| **Mutable Tag Attempt** | Reject `latest` or unpinned tags | `test_adversarial_mutable_tag_rejected` | **BLOCKED** |
| **Uppercase SHA Digest** | Reject non-lowercase hex digest | `test_adversarial_uppercase_sha_rejected` | **BLOCKED** |
| **Pulled Digest Tampering** | Reject pulled digest mismatch (`ExitCode 65`) | `test_adversarial_pulled_digest_mismatch_fails_closed` | **BLOCKED (65)** |
| **Failed Backup Hook** | Abort mutation before restart (`ExitCode 78`) | `test_adversarial_failed_backup_blocks_mutation` | **BLOCKED (78)** |
| **Missing / Empty Backup File** | Fail closed on 0-byte/missing backup artifact | `test_backup_execution_missing_file`, `test_backup_execution_empty_file` | **BLOCKED (78)** |
| **Stale Backup Record** | Reject backup records exceeding max age threshold | `test_backup_stale_validation` | **BLOCKED** |
| **Non-Additive Rollback Bypass** | Block automated app rollback, trigger `EMERGENCY_HALT` (`ExitCode 81`) | `test_adversarial_non_additive_migration_failure_triggers_emergency_halt` | **BLOCKED (81)** |
| **Additive Migration Auto-Rollback** | Execute safe app rollback to `ROLLED_BACK` | `test_adversarial_additive_migration_failure_triggers_safe_auto_rollback` | **ROLLED_BACK** |
| **Dropped Connection During Restart** | Transition to `UNKNOWN_REMOTE_STATE` (`ExitCode 125`), stop immediately | `test_adversarial_unknown_remote_state_stops_immediately_without_retry` | **HALTED (125)** |
| **Unauthenticated Restart Attempt** | Block deployment without valid OIDC token (`ExitCode 43`) | `test_adversarial_missing_auth_token_blocks_deployment` | **BLOCKED (43)** |
| **Running Digest Mismatch** | Reject post-deploy running container mismatch (`ExitCode 65`) | `test_post_deploy_verifier_running_digest_mismatch` | **BLOCKED (65)** |
| **Container Identity Mismatch** | Reject unexpected container runtime identity | `test_post_deploy_verifier_container_identity_mismatch` | **BLOCKED (125)** |

---

## 4. Frozen Baseline & Safety Verification

* **Phase 1 Schemas:** Unchanged (4 files in `schemas/`).
* **Phase 2B Contracts:** Unchanged (12 files in `upas_core/contracts/`).
* **Production Projects:** Untouched (`support_bot`, `tour_monitor`, `server-infrastructure`).
* **Git Operations:** No commit, no push, no merge, no production deploy executed.
