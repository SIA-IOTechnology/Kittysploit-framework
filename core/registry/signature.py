#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Signature system and trust store for the Registry Marketplace
"""

from __future__ import annotations

import os
import json
import hashlib
import base64
from typing import Optional, Dict, TYPE_CHECKING
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from core.output_handler import print_error, print_warning, print_success

if TYPE_CHECKING:
    # Only used for type hints; avoid runtime dependency/cycles.
    from core.encryption_manager import EncryptionManager


class RegistrySignatureManager:
    """Signature verification manager for the registry (read-only - no signing)"""
    
    SUPPORTED_ALGORITHMS = ["ED25519", "RSA-PSS"]
    DEFAULT_ALGORITHM = "ED25519"
    
    def __init__(
        self,
        encryption_manager: Optional["EncryptionManager"] = None,
        trust_store_path: Optional[str] = None,
    ):
        """
        Initialize the signature verification manager
        
        Args:
            encryption_manager: EncryptionManager instance (not used for verification)
            trust_store_path: Path to trust store (config/trust_store.json)
        """
        if trust_store_path is None:
            # Use config/trust_store.json in workspace
            config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config")
            os.makedirs(config_dir, exist_ok=True)
            trust_store_path = os.path.join(config_dir, "trust_store.json")
        
        self.trust_store_path = trust_store_path
        self.trust_store = self._load_trust_store()
        self.algorithm = self.DEFAULT_ALGORITHM
    
    def _load_trust_store(self) -> Dict[str, Dict[str, str]]:
        """Load trust store from JSON file"""
        if not os.path.exists(self.trust_store_path):
            return {}
        
        try:
            with open(self.trust_store_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print_warning(f"Error loading trust store: {e}")
            return {}
    
    def _save_trust_store(self):
        """Save trust store to JSON file"""
        try:
            with open(self.trust_store_path, 'w', encoding='utf-8') as f:
                json.dump(self.trust_store, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print_error(f"Error saving trust store: {e}")
    
    def verify_signature(self, manifest_content: str, signature: str, public_key_pem: str) -> bool:
        """
        Verify a manifest signature
        
        Args:
            manifest_content: Manifest content
            signature: Base64 signature
            public_key_pem: Public key in PEM format
            
        Returns:
            True if signature is valid
        """
        try:
            # Load public key
            public_key = load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Calculate manifest hash
            manifest_hash = hashlib.sha256(manifest_content.encode('utf-8')).hexdigest()
            
            # Decode signature
            signature_bytes = base64.b64decode(signature.encode('utf-8'))
            
            # Verify according to algorithm
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature_bytes, manifest_hash.encode('utf-8'))
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature_bytes,
                    manifest_hash.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:
                print_warning("Unsupported public key type")
                return False
            
            return True
            
        except InvalidSignature:
            print_warning("Invalid signature")
            return False
        except Exception as e:
            print_error(f"Error verifying signature: {e}")
            return False
    
    def add_trusted_publisher(self, publisher_name: str, public_key_pem: str):
        """
        Add a trusted publisher to the trust store
        
        Args:
            publisher_name: Publisher name
            public_key_pem: Public key in PEM format
        """
        self.trust_store[publisher_name] = {
            "public_key": public_key_pem,
            "algorithm": self._detect_algorithm(public_key_pem)
        }
        self._save_trust_store()
        print_success(f"Publisher {publisher_name} added to trust store")
    
    def is_publisher_trusted(self, publisher_name: str) -> bool:
        """Check if a publisher is in the trust store"""
        return publisher_name in self.trust_store
    
    def get_trusted_public_key(self, publisher_name: str) -> Optional[str]:
        """Get public key of a trusted publisher"""
        if publisher_name in self.trust_store:
            return self.trust_store[publisher_name].get("public_key")
        return None
    
    def _detect_algorithm(self, public_key_pem: str) -> str:
        """Detect algorithm of a public key"""
        try:
            public_key = load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                return "ED25519"
            elif isinstance(public_key, rsa.RSAPublicKey):
                return "RSA-PSS"
            else:
                return "UNKNOWN"
        except:
            return "UNKNOWN"
    
    def verify_bundle_integrity(self, bundle_path: str, expected_hash: str) -> bool:
        """
        Verify bundle integrity by comparing its hash
        
        Args:
            bundle_path: Path to bundle
            expected_hash: Expected SHA256 hash
            
        Returns:
            True if hash matches
        """
        try:
            from core.registry.manifest import ManifestParser
            actual_hash = ManifestParser.compute_bundle_hash(bundle_path)
            return actual_hash.lower() == expected_hash.lower()
        except Exception as e:
            print_error(f"Error verifying integrity: {e}")
            return False

