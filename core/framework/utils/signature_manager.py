#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Signature Manager - Gestion des signatures cryptographiques pour les modules
Utilise EncryptionManager comme base et ajoute les fonctionnalités de signature
"""

import os
import hashlib
import base64
import json
from typing import Optional, Dict, Any
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from core.encryption_manager import EncryptionManager
from core.framework.utils.policy_engine import ModuleSignature
from core.output_handler import print_error, print_warning


class SignatureManager:
    """Gestionnaire de signatures cryptographiques pour les modules"""
    
    def __init__(self, encryption_manager: Optional[EncryptionManager] = None):
        """
        Initialise le gestionnaire de signatures
        
        Args:
            encryption_manager: Instance d'EncryptionManager
        """
        self.encryption_manager = encryption_manager or EncryptionManager()
        self.keys_dir = os.path.join(self.encryption_manager.config_dir, "signing_keys")
        os.makedirs(self.keys_dir, exist_ok=True)
        self.algorithm = "ECDSA-SHA256"
    
    def generate_key_pair(self, signer_name: str) -> bool:
        """
        Génère une paire de clés pour un signataire
        
        Args:
            signer_name: Nom du signataire
            
        Returns:
            True si la génération a réussi
        """
        try:
            # Générer une clé privée ECDSA
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            
            # Sauvegarder la clé privée (chiffrée)
            private_key_path = os.path.join(self.keys_dir, f"{signer_name}_private.pem")
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
            public_key_path = os.path.join(self.keys_dir, f"{signer_name}_public.pem")
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            return True
        except Exception as e:
            print_error(f"Erreur lors de la génération de la paire de clés: {e}")
            return False
    
    def sign_module(
        self,
        module_code: str,
        signer: str
    ) -> Optional[ModuleSignature]:
        """
        Signe un module cryptographiquement
        
        Args:
            module_code: Code source du module
            signer: Nom du signataire
            
        Returns:
            Signature du module ou None en cas d'erreur
        """
        try:
            # Charger la clé privée
            private_key = self._load_private_key(signer)
            if not private_key:
                print_error(f"Clé privée non trouvée pour {signer}")
                return None
            
            # Calculer le hash du module
            module_hash = hashlib.sha256(module_code.encode('utf-8')).hexdigest()
            
            # Signer le hash
            signature_bytes = private_key.sign(
                module_hash.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            
            # Encoder la signature en base64
            signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
            
            # Créer l'objet signature
            signature = ModuleSignature(
                module_hash=module_hash,
                signature=signature_b64,
                signer=signer,
                timestamp=datetime.now().timestamp(),
                algorithm=self.algorithm
            )
            
            return signature
            
        except Exception as e:
            print_error(f"Erreur lors de la signature: {e}")
            return None
    
    def verify_signature(
        self,
        module_code: str,
        signature: ModuleSignature
    ) -> bool:
        """
        Vérifie la signature d'un module
        
        Args:
            module_code: Code source du module
            signature: Signature à vérifier
            
        Returns:
            True si la signature est valide
        """
        try:
            # Charger la clé publique
            public_key = self._load_public_key(signature.signer)
            if not public_key:
                print_warning(f"Clé publique non trouvée pour {signature.signer}")
                return False
            
            # Calculer le hash du module
            module_hash = hashlib.sha256(module_code.encode('utf-8')).hexdigest()
            
            # Vérifier que le hash correspond
            if module_hash != signature.module_hash:
                print_warning("Hash du module ne correspond pas à la signature")
                return False
            
            # Décoder la signature
            signature_bytes = base64.b64decode(signature.signature.encode('utf-8'))
            
            # Vérifier la signature
            public_key.verify(
                signature_bytes,
                module_hash.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            
            return True
            
        except InvalidSignature:
            print_warning("Signature invalide")
            return False
        except Exception as e:
            print_error(f"Erreur lors de la vérification de la signature: {e}")
            return False
    
    def _load_private_key(self, signer: str):
        """Charge la clé privée d'un signataire"""
        private_key_path = os.path.join(self.keys_dir, f"{signer}_private.pem")
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
    
    def _load_public_key(self, signer: str):
        """Charge la clé publique d'un signataire"""
        public_key_path = os.path.join(self.keys_dir, f"{signer}_public.pem")
        if not os.path.exists(public_key_path):
            return None
        
        try:
            with open(public_key_path, 'rb') as f:
                public_pem = f.read()
            
            public_key = load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
            return public_key
        except Exception as e:
            print_error(f"Erreur lors du chargement de la clé publique: {e}")
            return None

