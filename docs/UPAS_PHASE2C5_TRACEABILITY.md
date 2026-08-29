# UPAS Phase 2C-5 — CLI Harness & Lifecycle Integration Traceability Matrix

This document establishes formal architectural traceability between the frozen UPAS contracts, the Phase 2C-5 unified CLI harness, composite lifecycle state transitions, bypass prevention mechanisms, and automated test suites.

---

## 1. Traceability Mapping Matrix

| CLI Command | Lifecycle Scope | Integrated Primitives | Exit Code Mapping | Automated Test Suites |
| :--- | :--- | :--- | :---: | :--- |
| **`upas deploy`** | Full Release Lifecycle | `ProductionDeployer`, `ProductionHostGuard`, `AtomicHostLock`, `HostResourcePreflight`, `PreDeployBackupManager`, `SafeMigrationRunner`, `CanonicalArtifactVerifier`, `PostDeployVerifier`, `EvidenceCollector`, `AtomicEvidenceWriter` | `SUCCESS` (**0**), `PROD_AUTH_FAILED` (**43**), `BLOCKED_CONCURRENCY` (**75**), `DIGEST_MISMATCH` (**65**), `FAILED_BACKUP` (**78**), `MIGRATION_FAILED` (**70**), `EMERGENCY_HALT` (**81**), `UNKNOWN_REMOTE_STATE` (**125**) | `test_lifecycle_harness.py`, `test_adversarial_cli.py`, `test_deployer_pipeline.py` |
| **`upas verify`** | Post-Deploy Verification | `PostDeployVerifier`, `CanonicalArtifactVerifier` | `SUCCESS` (**0**), `DIGEST_MISMATCH` (**65**), `TESTS_FAILED` (**1**) | `test_cli_commands.py`, `test_verifier.py` |
| **`upas audit`** | Evidence Tamper Verification | `read_and_verify_persisted_evidence`, `EvidenceManifest` | `SUCCESS` (**0**), `TESTS_FAILED` (**1**) | `test_cli_commands.py`, `test_adversarial_cli.py`, `test_writer.py` |
| **`upas preflight`** | Host Resource Gate | `HostResourcePreflight` | `SUCCESS` (**0**), `FAILED_PREFLIGHT` (**79**) | `test_cli_commands.py`, `test_preflight.py` |
| **`upas lock`** | Concurrency Inspection | `AtomicHostLock` | `SUCCESS` (**0**), `BLOCKED_CONCURRENCY` (**75**) | `test_cli_commands.py`, `test_host_lock.py` |

---

## 2. CLI & Lifecycle Architecture

The unified CLI harness (`upas_core/cli`) orchestrates the complete Zero-Ops lifecycle without allowing manual shortcuts:

```text
User / CI Invocation: upas deploy --adapter upas.adapter.json --digest sha256:...
       │
       ▼
[ Security Flag Gatekeeper ] ──(Prohibited flags like --force, --approve, --no-auth)──> FAIL (Exit 43 / 44)
       │
       ▼
[ Adapter & Schema Loader ] ──(Validates against upas.adapter.schema.json)
       │
       ▼
[ Lifecycle State Machine ]
  1. PROD_APPROVAL_PENDING ──(HostGuard: OIDC JWT verification & JTI anti-replay)──> PROD_AUTHORIZED
  2. PROD_AUTHORIZED       ──(AtomicHostLock: OS file locking & liveness)─────────> LOCK_ACQUIRED
  3. LOCK_ACQUIRED         ──(HostResourcePreflight: RAM, disk, swap, load)──────> PREFLIGHT
  4. PREFLIGHT             ──(PreDeployBackupManager: Backup hook + SHA256)──────> PRE_DEPLOY_BACKUP
  5. PRE_DEPLOY_BACKUP     ──(SafeMigrationRunner: Phase 1 migration)────────────> MIGRATION
  6. MIGRATION             ──(CanonicalArtifactVerifier: immutable pull)─────────> PULL_BY_DIGEST
  7. PULL_BY_DIGEST        ──(Safe Service Restart; catch remote drops)──────────> RESTART
  8. RESTART               ──(PostDeployVerifier: Identity, digest, health, smoke)──> POST_DEPLOY_VERIFY
  9. POST_DEPLOY_VERIFY    ──(EvidenceCollector & AtomicEvidenceWriter)───────────> DEPLOYMENT_VERIFIED
       │
       ▼
[ Cryptographic Proof Output ]
  • <project>.evidence.json (Canonical RFC 8785 JSON with redacted secrets and hash chain)
  • <project>.manifest.json (Immutable binding with SHA256 digest and digital signature)
```

---

## 3. Security & Anti-Bypass Enforcements

1. **Strict Flag Scanning:** Any attempt to invoke `--force`, `-f`, `--approve`, `--skip-auth`, `--no-auth`, `--bypass-lock`, `--skip-backup`, `--skip-verify`, `--insecure`, or `--ignore-errors` is intercepted before parser dispatch and immediately rejected with `ExitCode.PROD_AUTH_FAILED` (43) / `ExitCode.SECURITY_VIOLATION`.
2. **Mandatory Authorization:** Unauthenticated invocations (missing or invalid OIDC token) are rejected with `ExitCode.PROD_AUTH_FAILED` (43).
3. **Immutable Digest Enforcement:** Mutable tags (e.g. `:latest`, `:v1.0.0`) are structurally rejected. Deployments require canonical immutable references matching `registry/app@sha256:<64 hex>`.
4. **Fail-Closed Verification:** `UNKNOWN = FAIL`. If remote host connection drops during container restart, transitions to `UNKNOWN_REMOTE_STATE` (125) with zero blind destructive retries.
5. **Two-Phase Migration Gate:** Non-additive schema changes strictly require two-phase protocol; failure during verification triggers `EMERGENCY_HALT` (81).
6. **Mandatory Evidence:** `NO EVIDENCE = NO VERIFIED RELEASE`. Failures during evidence writing prevent transitioning to verified release.

---

## 4. Frozen Baseline & Safety Verification

* **Phase 1 Schemas:** Unchanged (4 files in `schemas/`).
* **Phase 2B Contracts:** Unchanged (12 files in `upas_core/contracts/`).
* **Production Projects:** Untouched (`support_bot`, `tour_monitor`, `server-infrastructure`).
* **Git Operations:** No commit, no push, no merge, no production deploy executed.
