# UPAS Phase 2C-4 — Evidence & Audit Generation Primitives Traceability Matrix

This document establishes formal architectural traceability between the frozen UPAS contracts, the Phase 2C-4 Evidence and Audit Generation primitives, canonical serialization, cryptographic hash chaining, secret redaction, manifest integrity, adversarial threat models, and automated test suites.

---

## 1. Traceability Mapping Matrix

| Architectural Requirement | Phase 2B Contract / Schema | Runtime Implementation | Primary Failure Mode | Exit Code | Automated Test Suites |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Evidence Schema Compliance** | `EvidenceRecord`, `schemas/evidence.schema.json` | `EvidenceCollector` (`upas_core/evidence/collector.py`) | `INVALID_EVIDENCE` | **1** | `test_collector.py`, `test_adversarial_evidence.py` |
| **Deterministic Canonical Serialization** | `EvidenceRecord`, RFC 8785 canonical JSON | `to_canonical_json`, `to_canonical_bytes` (`upas_core/evidence/model.py`) | `SERIALIZATION_ERROR` | **1** | `test_model.py`, `test_adversarial_evidence.py` |
| **Cryptographic Hash Chaining** | `AuditEvent`, `EvidenceGenerator` | `AuditEvent`, `EvidenceCollector` (`upas_core/evidence/collector.py`) | `HASH_CHAIN_CORRUPTED` | **1** | `test_collector.py`, `test_adversarial_evidence.py` |
| **Cryptographic Manifest & Signing** | `EvidenceSigner` (Protocol) | `EvidenceManifest`, `HashOnlySigner`, `AsymmetricEvidenceSigner` (`upas_core/evidence/manifest.py`, `signer.py`) | `MANIFEST_MISMATCH` | **1** | `test_manifest.py`, `test_signer.py` |
| **Fail-Safe Atomic Persistence** | POSIX/NT atomic replace + `fsync` | `AtomicEvidenceWriter` (`upas_core/evidence/writer.py`) | `WRITE_FAILED` | **1** | `test_writer.py`, `test_adversarial_evidence.py` |
| **Automated Secret Redaction** | Security Invariant: Zero Credential Leakage | `SecretRedactor` (`upas_core/evidence/model.py`) | `SECRET_LEAK` | **1** | `test_model.py`, `test_adversarial_evidence.py` |
| **Release Gating Invariant** | `NO EVIDENCE = NO VERIFIED RELEASE` | `ProductionDeployer` (`upas_core/deployment/deployer.py`) | `MISSING_EVIDENCE` | **1** | `test_deployer_pipeline.py` |

---

## 2. Evidence Architecture & Canonical Data Flow

The evidence subsystem guarantees that all mutations produce immutable, verifiable proof of authorization, execution, and outcomes:

```text
Pipeline Execution
       ↓
EvidenceCollector (Records events, steps, authoritative sources)
       ↓
SecretRedactor (Deep scan: JWT, Bearer, Private Keys, URIs redacted)
       ↓
Canonical JSON Serialization (Deterministic key sorting, UTF-8, no NaN)
       ↓
SHA-256 Hash Chaining (AuditEvent[n].previous_hash == AuditEvent[n-1].event_hash)
       ↓
EvidenceManifest Generation (Binds operation_id, artifact digest, verdict, SHA-256)
       ↓
Atomic Write (Write to temp -> fsync -> atomic rename)
       ↓
Post-Persist Tamper Verification (Recomputes SHA-256 and validates against manifest)
```

---

## 3. Secret Redaction Model

`SecretRedactor` automatically intercepts and strips credentials from all evidence fields and nested data structures:
* **Raw JWTs:** `eyJ...` tokens replaced with `[REDACTED_JWT_TOKEN]`.
* **Bearer Headers:** `Authorization: Bearer <token>` replaced with `Bearer [REDACTED_TOKEN]`.
* **PEM Private Keys:** `-----BEGIN ... PRIVATE KEY-----` replaced with `[REDACTED_PRIVATE_KEY]`.
* **Database URI Credentials:** `postgres://user:pass@host` replaced with `://[USER]:[REDACTED_PASSWORD]@`.
* **Generic Secrets:** Fields named `password`, `secret`, `api_key`, `token`, `private_key` replaced with `[REDACTED_SECRET]`.

---

## 4. Adversarial Threat Model Verification

All Phase 2C-4 adversarial scenarios are tested in automated suites:

| Adversarial Attack / Threat Scenario | Target Behavior | Test Name | Result |
| :--- | :--- | :--- | :---: |
| **Artifact Digest Tampering** | Manifest SHA256 mismatch detected | `test_adversarial_tamper_artifact_digest` | **BLOCKED** |
| **Actor Impersonation** | Manifest SHA256 mismatch detected | `test_adversarial_tamper_actor` | **BLOCKED** |
| **Commit SHA Modification** | Manifest SHA256 mismatch detected | `test_adversarial_tamper_commit_sha` | **BLOCKED** |
| **Lifecycle State Tampering** | Manifest SHA256 mismatch detected | `test_adversarial_tamper_lifecycle_state` | **BLOCKED** |
| **Audit Event Deletion** | Hash chain break detected (`verify_hash_chain == False`) | `test_adversarial_hash_chain_deletion_and_reordering` | **BLOCKED** |
| **Audit Event Reordering** | Hash chain break detected (`verify_hash_chain == False`) | `test_adversarial_hash_chain_deletion_and_reordering` | **BLOCKED** |
| **Secret Leakage Attempt** | All tokens, private keys, and passwords redacted | `test_adversarial_secret_leakage_redaction` | **SANITIZED** |
| **Disk Write Interruption** | Fail closed on invalid target path; no partial files | `test_adversarial_atomic_writer_invalid_target_dir` | **BLOCKED** |
| **Persisted File Tampering** | Disk tamper detected upon read verification | `test_tampered_evidence_file_fails_verification` | **BLOCKED** |

---

## 5. Frozen Baseline & Safety Verification

* **Phase 1 Schemas:** Unchanged (`schemas/evidence.schema.json` and all others unmodified).
* **Phase 2B Contracts:** Unchanged (`upas_core/contracts/evidence.py` and all others unmodified).
* **Production Projects:** Untouched (`support_bot`, `tour_monitor`, `server-infrastructure`).
* **Git Operations:** No commit, no push, no merge, no production deploy executed.
