"""
Signature service for transaction receipts

This service provides an interface for signing transaction receipts.
For MVP: local RSA keypair stored in gateway/.keys/ (dev-only)
For production: should be replaced with KMS without changing interface
"""

import os
import json
import base64
import hashlib
from typing import Dict, Any
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class SignerService:
    """Service for signing transaction receipts."""
    
    def __init__(self, keys_dir: str = None):
        """
        Initialize signer service.
        
        Args:
            keys_dir: Directory for storing keys (default: gateway/.keys/)
        """
        if keys_dir is None:
            keys_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                '.keys'
            )
        
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Load or generate keypair
        self._ensure_keypair()
    
    def _ensure_keypair(self):
        """Ensure RSA keypair exists, generate if not."""
        private_key_path = self.keys_dir / "private_key.pem"
        public_key_path = self.keys_dir / "public_key.pem"
        
        if private_key_path.exists() and public_key_path.exists():
            # Load existing keys
            with open(private_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            with open(public_key_path, "rb") as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        else:
            # Generate new keypair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # Save keys
            with open(private_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(public_key_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            print(f"Generated new RSA keypair in {self.keys_dir}")
    
    def get_key_id(self) -> str:
        """
        Get the key ID (fingerprint) for the current public key.
        
        Returns:
            Key ID as "sha256:<hex>"
        """
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashlib.sha256(public_bytes).hexdigest()
        return f"sha256:{key_hash}"
    
    def sign_bytes(self, message_bytes: bytes) -> Dict[str, Any]:
        """
        Sign a message with the private key.
        
        Args:
            message_bytes: Message to sign
            
        Returns:
            Dictionary with:
            - alg: "RS256"
            - key_id: Key identifier
            - signature_b64: Base64-encoded signature
        """
        signature = self.private_key.sign(
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return {
            "alg": "RS256",
            "key_id": self.get_key_id(),
            "signature_b64": base64.b64encode(signature).decode('utf-8')
        }
    
    def get_public_jwk(self, key_id: str = None) -> Dict[str, Any]:
        """
        Get the public key as a JWK.
        
        Args:
            key_id: Optional key ID (currently only one key supported)
            
        Returns:
            JWK dictionary
        """
        public_numbers = self.public_key.public_numbers()
        
        # Convert to JWK format
        n = public_numbers.n
        e = public_numbers.e
        
        # Convert to base64url encoding
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
        
        n_b64 = base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('=')
        e_b64 = base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('=')
        
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.get_key_id(),
            "n": n_b64,
            "e": e_b64
        }


# Singleton instance for the application
_signer_instance = None


def get_signer() -> SignerService:
    """Get or create the singleton signer instance."""
    global _signer_instance
    if _signer_instance is None:
        _signer_instance = SignerService()
    return _signer_instance
