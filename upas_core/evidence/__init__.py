"""
UPAS Evidence & Audit Generation Module.
Provides cryptographic audit record generation, canonical serialization,
SHA-256 hash-chaining, manifest creation, and atomic persistence.
"""

from upas_core.evidence.model import (
    AuditEvent,
    SecretRedactor,
    compute_evidence_hash,
    to_canonical_bytes,
    to_canonical_json,
)
from upas_core.evidence.collector import EvidenceCollector
from upas_core.evidence.signer import (
    AsymmetricEvidenceSigner,
    EvidenceSigner,
    HashOnlySigner,
)
from upas_core.evidence.manifest import (
    EvidenceManifest,
    generate_manifest,
    verify_evidence_against_manifest,
)
from upas_core.evidence.writer import (
    AtomicEvidenceWriter,
    read_and_verify_persisted_evidence,
)

__all__ = [
    "AuditEvent",
    "SecretRedactor",
    "compute_evidence_hash",
    "to_canonical_bytes",
    "to_canonical_json",
    "EvidenceCollector",
    "EvidenceSigner",
    "HashOnlySigner",
    "AsymmetricEvidenceSigner",
    "EvidenceManifest",
    "generate_manifest",
    "verify_evidence_against_manifest",
    "AtomicEvidenceWriter",
    "read_and_verify_persisted_evidence",
]
