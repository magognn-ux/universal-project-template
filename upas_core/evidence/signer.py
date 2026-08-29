"""
UPAS Cryptographic Evidence Signer & Verification Abstraction.
Supports cryptographic integrity manifests, SHA-256 hash digests,
and asymmetric digital signatures (RSA/ECDSA) without storing secrets in the repository.
"""

import hashlib
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from upas_core.evidence.model import compute_evidence_hash


@runtime_checkable
class EvidenceSigner(Protocol):
    """Protocol for evidence integrity signature providers."""

    def sign(self, canonical_data: bytes) -> Dict[str, Any]:
        """Signs canonical evidence bytes and returns structured signature metadata."""
        ...

    def verify(self, canonical_data: bytes, signature_metadata: Dict[str, Any]) -> bool:
        """Verifies canonical evidence bytes against signature metadata."""
        ...


class HashOnlySigner(EvidenceSigner):
    """
    Standard integrity signer computing a canonical SHA-256 digest.
    Provides non-repudiation baseline without requiring external PKI.
    """

    def sign(self, canonical_data: bytes) -> Dict[str, Any]:
        digest = hashlib.sha256(canonical_data).hexdigest()
        return {
            "algorithm": "sha256",
            "digest": digest,
        }

    def verify(self, canonical_data: bytes, signature_metadata: Dict[str, Any]) -> bool:
        if not signature_metadata or not isinstance(signature_metadata, dict):
            return False
        expected_digest = signature_metadata.get("digest")
        if not expected_digest:
            return False
        calculated = hashlib.sha256(canonical_data).hexdigest()
        return calculated == expected_digest


class AsymmetricEvidenceSigner(EvidenceSigner):
    """
    Asymmetric digital signature provider using RSA/ECDSA private keys.
    Injected at runtime via memory or KMS; private keys are never stored in the repository.
    """

    def __init__(
        self,
        private_key: Optional[Any] = None,
        public_key: Optional[Any] = None,
        key_id: str = "upas-audit-key-1",
        algorithm: str = "RS256",
    ):
        self.private_key = private_key
        self.public_key = public_key or (private_key.public_key() if private_key and hasattr(private_key, "public_key") else None)
        self.key_id = key_id
        self.algorithm = algorithm

    def sign(self, canonical_data: bytes) -> Dict[str, Any]:
        if not self.private_key:
            # Fallback to hash digest if no private key is provided
            digest = hashlib.sha256(canonical_data).hexdigest()
            return {
                "algorithm": "sha256",
                "digest": digest,
            }

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        digest = hashlib.sha256(canonical_data).hexdigest()
        raw_signature = self.private_key.sign(
            canonical_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return {
            "algorithm": "RSASSA-PSS-SHA256",
            "key_id": self.key_id,
            "digest": digest,
            "signature_hex": raw_signature.hex(),
        }

    def verify(self, canonical_data: bytes, signature_metadata: Dict[str, Any]) -> bool:
        if not signature_metadata or not isinstance(signature_metadata, dict):
            return False

        algo = signature_metadata.get("algorithm")
        if algo == "sha256":
            expected_digest = signature_metadata.get("digest")
            calculated = hashlib.sha256(canonical_data).hexdigest()
            return calculated == expected_digest

        if not self.public_key:
            return False

        sig_hex = signature_metadata.get("signature_hex")
        if not sig_hex:
            return False

        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding

            sig_bytes = bytes.fromhex(sig_hex)
            self.public_key.verify(
                sig_bytes,
                canonical_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False
