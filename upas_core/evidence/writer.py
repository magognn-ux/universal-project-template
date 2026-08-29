"""
UPAS Atomic Evidence Persistence & Tamper Verification.
Guarantees fail-safe atomic writes (fsync + atomic replace) and tamper detection.
"""

import json
import os
import tempfile
import time
from typing import Any, Dict, Optional, Tuple, Union

from upas_core.contracts.enums import ExitCode
from upas_core.contracts.errors import InvalidEvidenceError
from upas_core.contracts.evidence import EvidenceRecord
from upas_core.evidence.manifest import (
    EvidenceManifest,
    generate_manifest,
    verify_evidence_against_manifest,
)
from upas_core.evidence.model import compute_evidence_hash, to_canonical_bytes, to_canonical_json
from upas_core.evidence.signer import EvidenceSigner


class AtomicEvidenceWriter:
    """
    Persists evidence records and cryptographic manifests using atomic filesystem primitives.
    Prevents partial or corrupted evidence from being left on disk.
    """

    def __init__(self, signer: Optional[EvidenceSigner] = None):
        self.signer = signer

    def _write_file_atomically(self, target_path: str, data_bytes: bytes) -> None:
        """Writes bytes to a temporary file, fsyncs, and atomically renames to target_path."""
        abs_target = os.path.abspath(target_path)
        target_dir = os.path.dirname(abs_target)
        temp_path = None

        try:
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            prefix = f".tmp_{os.path.basename(abs_target)}_"
            temp_fd, temp_path = tempfile.mkstemp(prefix=prefix, dir=target_dir)

            with os.fdopen(temp_fd, "wb") as f:
                f.write(data_bytes)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace (guaranteed atomic on POSIX and Windows NT)
            os.replace(temp_path, abs_target)
        except Exception as exc:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise InvalidEvidenceError(f"Failed to atomically write '{abs_target}': {exc}") from exc

    def write_evidence_and_manifest(
        self,
        evidence: Union[EvidenceRecord, Dict[str, Any]],
        output_evidence_path: str,
        output_manifest_path: Optional[str] = None,
    ) -> Tuple[str, str, EvidenceManifest]:
        """
        Atomically writes canonical evidence JSON and its associated cryptographic manifest.
        Returns (evidence_path, manifest_path, EvidenceManifest).
        """
        # 1. Canonical bytes
        canonical_bytes = to_canonical_bytes(evidence)

        # 2. Generate cryptographic manifest
        manifest = generate_manifest(canonical_bytes, signer=self.signer)
        manifest_bytes = manifest.to_canonical_bytes()

        # 3. Determine manifest path if not provided
        abs_evidence_path = os.path.abspath(output_evidence_path)
        if not output_manifest_path:
            abs_manifest_path = f"{abs_evidence_path}.manifest.json"
        else:
            abs_manifest_path = os.path.abspath(output_manifest_path)

        # 4. Atomically persist both files
        self._write_file_atomically(abs_evidence_path, canonical_bytes)
        self._write_file_atomically(abs_manifest_path, manifest_bytes)

        return abs_evidence_path, abs_manifest_path, manifest


def read_and_verify_persisted_evidence(
    evidence_path: str,
    manifest_path: str,
    signer: Optional[EvidenceSigner] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[EvidenceManifest], Optional[str]]:
    """
    Reads evidence and manifest files from disk and verifies their cryptographic integrity.
    Returns (is_valid, evidence_dict, manifest, error_message).
    """
    if not os.path.exists(evidence_path):
        return False, None, None, f"Evidence file not found: '{evidence_path}'"
    if not os.path.exists(manifest_path):
        return False, None, None, f"Manifest file not found: '{manifest_path}'"

    # Read raw bytes
    try:
        with open(evidence_path, "rb") as f:
            evidence_bytes = f.read()
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_json = json.load(f)
    except Exception as exc:
        return False, None, None, f"Failed to read evidence/manifest files: {exc}"

    try:
        manifest = EvidenceManifest(
            manifest_id=manifest_json["manifest_id"],
            operation_id=manifest_json["operation_id"],
            correlation_id=manifest_json["correlation_id"],
            evidence_sha256=manifest_json["evidence_sha256"],
            artifact_digest=manifest_json["artifact_digest"],
            final_state=manifest_json["final_state"],
            final_exit_code=manifest_json["final_exit_code"],
            generated_at=manifest_json["generated_at"],
            schema_version=manifest_json.get("schema_version", "1.0.0"),
            signature=manifest_json.get("signature"),
        )
    except Exception as exc:
        return False, None, None, f"Malformed EvidenceManifest: {exc}"

    is_valid = verify_evidence_against_manifest(manifest, evidence_bytes, signer=signer)
    if not is_valid:
        return False, None, manifest, "Cryptographic integrity verification failed: evidence has been tampered with or modified"

    try:
        evidence_dict = json.loads(evidence_bytes.decode("utf-8"))
    except Exception as exc:
        return False, None, manifest, f"Failed to decode evidence JSON: {exc}"

    return True, evidence_dict, manifest, None
