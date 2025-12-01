#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Système de signature et trust store pour le Registry Marketplace
"""

import os
import json
import hashlib
import base64
from typing import Optional, Dict, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from core.encryption_manager import EncryptionManager
from core.output_handler import print_error, print_warning, print_success


class RegistrySignatureManager:
    """Gestionnaire de signatures pour le registry"""
    
    SUPPORTED_ALGORITHMS = ["ED25519", "RSA-PSS"]
    DEFAULT_ALGORITHM = "ED25519"
    
    def __init__(self, encryption_manager: Optional[EncryptionManager] = None, trust_store_path: Optional[str] = None):
        """
        Initialise le gestionnaire de signatures
        
        Args:
            encryption_manager: Instance d'EncryptionManager pour stocker les clés privées
            trust_store_path: Chemin vers le trust store (config/trust_store.json)
        """
        self.encryption_manager = encryption_manager or EncryptionManager()
        self.keys_dir = os.path.join(self.encryption_manager.config_dir, "registry_keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        
        if trust_store_path is None:
            # Utiliser config/trust_store.json dans le workspace
            config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config")
            os.makedirs(config_dir, exist_ok=True)
            trust_store_path = os.path.join(config_dir, "trust_store.json")
        
        self.trust_store_path = trust_store_path
        self.trust_store = self._load_trust_store()
        self.algorithm = self.DEFAULT_ALGORITHM
    
    def _load_trust_store(self) -> Dict[str, Dict[str, str]]:
        """Charge le trust store depuis le fichier JSON"""
        if not os.path.exists(self.trust_store_path):
            return {}
        
        try:
            with open(self.trust_store_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print_warning(f"Erreur lors du chargement du trust store: {e}")
            return {}
    
    def _save_trust_store(self):
        """Sauvegarde le trust store dans le fichier JSON"""
        try:
            with open(self.trust_store_path, 'w', encoding='utf-8') as f:
                json.dump(self.trust_store, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print_error(f"Erreur lors de la sauvegarde du trust store: {e}")
    
    def generate_key_pair(self, publisher_name: str, algorithm: str = None) -> tuple[bool, Optional[str], Optional[str]]:
        """
        Génère une paire de clés pour un éditeur
        
        Args:
            publisher_name: Nom de l'éditeur
            algorithm: Algorithme à utiliser (ED25519 ou RSA-PSS), None pour défaut
            
        Returns:
            (success, public_key_pem, private_key_path)
        """
        algorithm = algorithm or self.DEFAULT_ALGORITHM
        
        try:
            if algorithm == "ED25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
                public_key = private_key.public_key()
            elif algorithm == "RSA-PSS":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
            else:
                print_error(f"Algorithme non supporté: {algorithm}")
                return False, None, None
            
            # Sauvegarder la clé privée (chiffrée)
            private_key_path = os.path.join(self.keys_dir, f"{publisher_name}_private.pem")
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Chiffrer avec EncryptionManager si disponible
            if self.encryption_manager._is_initialized:
                encrypted_private = self.encryption_manager.encrypt_data(private_pem.decode('utf-8'))
                with open(private_key_path, 'w') as f:
                    f.write(encrypted_private)
            else:
                with open(private_key_path, 'wb') as f:
                    f.write(private_pem)
            
            # Sauvegarder la clé publique
            public_key_path = os.path.join(self.keys_dir, f"{publisher_name}_public.pem")
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            # Retourner la clé publique en PEM
            public_key_pem = public_pem.decode('utf-8')
            
            print_success(f"Paire de clés générée pour {publisher_name} (algorithme: {algorithm})")
            return True, public_key_pem, private_key_path
            
        except Exception as e:
            print_error(f"Erreur lors de la génération de la paire de clés: {e}")
            return False, None, None
    
    def sign_manifest(self, manifest_content: str, publisher_name: str) -> Optional[str]:
        """
        Signe un manifest
        
        Args:
            manifest_content: Contenu du manifest (TOML ou JSON)
            publisher_name: Nom de l'éditeur (pour charger la clé privée)
            
        Returns:
            Signature en base64 ou None en cas d'erreur
        """
        try:
            private_key = self._load_private_key(publisher_name)
            if not private_key:
                print_error(f"Clé privée non trouvée pour {publisher_name}")
                return None
            
            # Calculer le hash du manifest
            manifest_hash = hashlib.sha256(manifest_content.encode('utf-8')).hexdigest()
            
            # Signer selon l'algorithme
            if isinstance(private_key, ed25519.Ed25519PrivateKey):
                signature_bytes = private_key.sign(manifest_hash.encode('utf-8'))
            elif isinstance(private_key, rsa.RSAPrivateKey):
                signature_bytes = private_key.sign(
                    manifest_hash.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:
                print_error("Type de clé non supporté")
                return None
            
            # Encoder en base64
            signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
            return signature_b64
            
        except Exception as e:
            print_error(f"Erreur lors de la signature: {e}")
            return None
    
    def verify_signature(self, manifest_content: str, signature: str, public_key_pem: str) -> bool:
        """
        Vérifie la signature d'un manifest
        
        Args:
            manifest_content: Contenu du manifest
            signature: Signature en base64
            public_key_pem: Clé publique en PEM
            
        Returns:
            True si la signature est valide
        """
        try:
            # Charger la clé publique
            public_key = load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Calculer le hash du manifest
            manifest_hash = hashlib.sha256(manifest_content.encode('utf-8')).hexdigest()
            
            # Décoder la signature
            signature_bytes = base64.b64decode(signature.encode('utf-8'))
            
            # Vérifier selon l'algorithme
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
                print_warning("Type de clé publique non supporté")
                return False
            
            return True
            
        except InvalidSignature:
            print_warning("Signature invalide")
            return False
        except Exception as e:
            print_error(f"Erreur lors de la vérification de la signature: {e}")
            return False
    
    def add_trusted_publisher(self, publisher_name: str, public_key_pem: str):
        """
        Ajoute un éditeur de confiance au trust store
        
        Args:
            publisher_name: Nom de l'éditeur
            public_key_pem: Clé publique en PEM
        """
        self.trust_store[publisher_name] = {
            "public_key": public_key_pem,
            "algorithm": self._detect_algorithm(public_key_pem)
        }
        self._save_trust_store()
        print_success(f"Éditeur {publisher_name} ajouté au trust store")
    
    def is_publisher_trusted(self, publisher_name: str) -> bool:
        """Vérifie si un éditeur est dans le trust store"""
        return publisher_name in self.trust_store
    
    def get_trusted_public_key(self, publisher_name: str) -> Optional[str]:
        """Récupère la clé publique d'un éditeur de confiance"""
        if publisher_name in self.trust_store:
            return self.trust_store[publisher_name].get("public_key")
        return None
    
    def _load_private_key(self, publisher_name: str):
        """Charge la clé privée d'un éditeur"""
        private_key_path = os.path.join(self.keys_dir, f"{publisher_name}_private.pem")
        if not os.path.exists(private_key_path):
            return None
        
        try:
            with open(private_key_path, 'r') as f:
                private_data = f.read()
            
            # Déchiffrer si nécessaire
            if self.encryption_manager._is_initialized:
                try:
                    private_pem = self.encryption_manager.decrypt_data(private_data)
                    if isinstance(private_pem, str):
                        private_pem = private_pem.encode('utf-8')
                except:
                    # Peut-être pas chiffré, essayer directement
                    private_pem = private_data.encode('utf-8')
            else:
                private_pem = private_data.encode('utf-8')
            
            # Charger la clé
            private_key = load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            return private_key
        except Exception as e:
            print_error(f"Erreur lors du chargement de la clé privée: {e}")
            return None
    
    def _detect_algorithm(self, public_key_pem: str) -> str:
        """Détecte l'algorithme d'une clé publique"""
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
        Vérifie l'intégrité d'un bundle en comparant son hash
        
        Args:
            bundle_path: Chemin vers le bundle
            expected_hash: Hash SHA256 attendu
            
        Returns:
            True si le hash correspond
        """
        try:
            from core.registry.manifest import ManifestParser
            actual_hash = ManifestParser.compute_bundle_hash(bundle_path)
            return actual_hash.lower() == expected_hash.lower()
        except Exception as e:
            print_error(f"Erreur lors de la vérification d'intégrité: {e}")
            return False

