#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Outil de packaging pour créer des bundles d'extensions (.kext)
"""

import os
import zipfile
import shutil
import tempfile
from typing import List, Optional
from pathlib import Path

from core.registry.manifest import ManifestParser, ExtensionManifest
from core.registry.signature import RegistrySignatureManager
from core.output_handler import print_error, print_warning, print_success, print_info


class ExtensionPackager:
    """Outil pour créer des bundles d'extensions"""
    
    def __init__(self, signature_manager: Optional[RegistrySignatureManager] = None):
        """
        Initialise le packager
        
        Args:
            signature_manager: Gestionnaire de signatures
        """
        self.signature_manager = signature_manager or RegistrySignatureManager()
    
    def create_bundle(
        self,
        source_dir: str,
        manifest_path: str,
        output_path: str,
        publisher_name: Optional[str] = None,
        sign: bool = True
    ) -> bool:
        """
        Crée un bundle d'extension
        
        Args:
            source_dir: Répertoire source contenant les fichiers de l'extension
            manifest_path: Chemin vers extension.toml
            output_path: Chemin de sortie pour le bundle (.kext)
            publisher_name: Nom de l'éditeur (pour signer)
            sign: Signer le bundle
            
        Returns:
            True si le bundle a été créé avec succès
        """
        try:
            print_info(f"Creating bundle from {source_dir}...")
            
            # Parser le manifest
            manifest = ManifestParser.parse(manifest_path)
            if not manifest:
                print_error("Error parsing manifest")
                return False
            
            # Valider le manifest
            is_valid, errors = ManifestParser.validate(manifest)
            if not is_valid:
                print_error(f"Invalid manifest: {', '.join(errors)}")
                return False
            
            # Calculer les hashes des fichiers
            print_info("Calculating file hashes...")
            payload_hashes = {}
            for root, dirs, files in os.walk(source_dir):
                # Ignorer les fichiers de build
                dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', '.pytest_cache']]
                
                for file in files:
                    if file.startswith('.') or file.endswith('.pyc'):
                        continue
                    
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, source_dir)
                    file_hash = ManifestParser.compute_file_hash(file_path)
                    payload_hashes[rel_path] = file_hash
            
            manifest.payload_hashes = payload_hashes
            
            # Signer le manifest si demandé
            if sign and publisher_name:
                print_info(f"Signing manifest by {publisher_name}...")
                manifest_toml = manifest.to_toml()
                signature = self.signature_manager.sign_manifest(manifest_toml, publisher_name)
                if signature:
                    manifest.signature = signature
                    # Récupérer la clé publique
                    public_key = self.signature_manager.get_trusted_public_key(publisher_name)
                    if not public_key:
                        # Essayer de charger depuis le fichier
                        keys_dir = os.path.join(self.signature_manager.keys_dir)
                        public_key_path = os.path.join(keys_dir, f"{publisher_name}_public.pem")
                        if os.path.exists(public_key_path):
                            with open(public_key_path, 'rb') as f:
                                public_key = f.read().decode('utf-8')
                    
                    if public_key:
                        manifest.public_key = public_key
                else:
                    print_warning("Signature failed - bundle created without signature")
            
            # Créer le bundle
            print_info(f"Creating bundle {output_path}...")
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Ajouter tous les fichiers du répertoire source
                for root, dirs, files in os.walk(source_dir):
                    # Ignorer les fichiers de build
                    dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', '.pytest_cache']]
                    
                    for file in files:
                        if file.startswith('.') or file.endswith('.pyc'):
                            continue
                        
                        # Exclure extension.toml du répertoire source car on l'ajoute manuellement après
                        if file == 'extension.toml':
                            continue
                        
                        # Exclure les anciens bundles .kext pour éviter qu'ils soient inclus dans le nouveau bundle
                        if file.endswith('.kext') or file.endswith('.zip'):
                            continue
                        
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, source_dir)
                        zipf.write(file_path, arcname)
                
                # Ajouter le manifest mis à jour (écrase celui du répertoire source s'il existe)
                manifest_toml = manifest.to_toml()
                zipf.writestr("extension.toml", manifest_toml)
            
            # Vérifier le bundle
            bundle_hash = ManifestParser.compute_bundle_hash(output_path)
            bundle_size = os.path.getsize(output_path)
            
            print_success(f"Bundle created: {output_path}")
            print_status(f"Hash SHA256: {bundle_hash}")
            print_status(f"Size: {bundle_size} bytes")
            
            return True
            
        except Exception as e:
            print_error(f"Error creating bundle: {e}")
            return False
    
    def extract_bundle(self, bundle_path: str, extract_dir: str) -> bool:
        """
        Extrait un bundle
        
        Args:
            bundle_path: Chemin vers le bundle
            extract_dir: Répertoire de destination
            
        Returns:
            True si l'extraction a réussi
        """
        try:
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(bundle_path, 'r') as zipf:
                zipf.extractall(extract_dir)
            
            print_success(f"Bundle extracted to {extract_dir}")
            return True
        except Exception as e:
            print_error(f"Error extracting bundle: {e}")
            return False
    
    def verify_bundle(self, bundle_path: str) -> tuple[bool, Optional[ExtensionManifest]]:
        """
        Vérifie l'intégrité d'un bundle
        
        Args:
            bundle_path: Chemin vers le bundle
            
        Returns:
            (is_valid, manifest)
        """
        try:
            # Extraire temporairement
            with tempfile.TemporaryDirectory() as tmpdir:
                with zipfile.ZipFile(bundle_path, 'r') as zipf:
                    zipf.extractall(tmpdir)
                
                # Chercher le manifest
                manifest_path = os.path.join(tmpdir, "extension.toml")
                if not os.path.exists(manifest_path):
                    print_error("Manifest not found in bundle")
                    return False, None
                
                # Parser le manifest
                manifest = ManifestParser.parse(manifest_path)
                if not manifest:
                    print_error("Error parsing manifest")
                    return False, None
                
                # Valider le manifest
                is_valid, errors = ManifestParser.validate(manifest)
                if not is_valid:
                    print_error(f"Invalid manifest: {', '.join(errors)}")
                    return False, None
                
                # Vérifier les hashes des fichiers
                for rel_path, expected_hash in manifest.payload_hashes.items():
                    file_path = os.path.join(tmpdir, rel_path)
                    if not os.path.exists(file_path):
                        print_warning(f"File missing in bundle: {rel_path}")
                        continue
                    
                    actual_hash = ManifestParser.compute_file_hash(file_path)
                    if actual_hash != expected_hash:
                        print_error(f"Invalid hash for {rel_path}")
                        return False, None
                
                # Vérifier la signature si présente
                if manifest.signature and manifest.public_key:
                    manifest_content = open(manifest_path, 'r', encoding='utf-8').read()
                    if not self.signature_manager.verify_signature(
                        manifest_content,
                        manifest.signature,
                        manifest.public_key
                    ):
                        print_error("Invalid signature")
                        return False, None
                
                return True, manifest
                
        except Exception as e:
            print_error(f"Error verifying bundle: {e}")
            return False, None

