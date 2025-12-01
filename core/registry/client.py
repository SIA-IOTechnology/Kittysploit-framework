#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Client Marketplace - Client pour interagir avec le registry
"""

import os
import shutil
import zipfile
import tempfile
from typing import Optional, Dict, List, Any
import requests

try:
    from core.registry.manifest import ManifestParser, ExtensionManifest
    from core.registry.signature import RegistrySignatureManager
    REGISTRY_AVAILABLE = True
except ImportError as e:
    REGISTRY_AVAILABLE = False
    REGISTRY_IMPORT_ERROR = str(e)

from core.output_handler import print_error, print_warning, print_success, print_info


class ExtensionClient:
    """Client pour le marketplace d'extensions"""
    
    def __init__(
        self,
        registry_url: Optional[str] = None,
        extensions_dir: str = "extensions",
        signature_manager: Optional[RegistrySignatureManager] = None
    ):
        """
        Initialise le client marketplace
        
        Args:
            registry_url: URL du serveur registry distant (défaut: depuis config ou registry.kittysploit.com)
            extensions_dir: Répertoire local pour installer les extensions
            signature_manager: Gestionnaire de signatures
        """
        if not REGISTRY_AVAILABLE:
            raise ImportError(f"Registry marketplace not available: {REGISTRY_IMPORT_ERROR}")
        
        # URL du registry distant (service centralisé KittySploit)
        if registry_url is None:
            # Essayer de charger depuis la config
            try:
                from core.config import Config
                config = Config.get_instance()
                registry_url = config.get_config_value_by_path('registry.url')
            except:
                pass
            
            # Défaut : service centralisé KittySploit
            if not registry_url:
                registry_url = "https://registry.kittysploit.com"
        
        self.registry_url = registry_url.rstrip('/')
        self.extensions_dir = extensions_dir
        try:
            self.signature_manager = signature_manager or RegistrySignatureManager()
        except Exception as e:
            print_warning(f"Could not initialize signature manager: {e}")
            self.signature_manager = None
        os.makedirs(extensions_dir, exist_ok=True)
    
    def list_extensions(
        self,
        extension_type: Optional[str] = None,
        is_free: Optional[bool] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Dict[str, Any]:
        """
        Liste les extensions disponibles
        
        Returns:
            Dict avec les extensions et métadonnées de pagination
        """
        try:
            params = {
                "page": page,
                "per_page": per_page
            }
            if extension_type:
                params["type"] = extension_type
            if is_free is not None:
                params["is_free"] = is_free
            if search:
                params["search"] = search
            
            response = requests.get(
                f"{self.registry_url}/api/registry/extensions",
                params=params,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            print_error(f"Could not connect to registry server at {self.registry_url}")
            print_warning("Make sure the API server is running (kittyapi.py)")
            return {"extensions": [], "total": 0, "page": 1, "per_page": per_page}
        except requests.exceptions.Timeout:
            print_error("Request to registry server timed out")
            return {"extensions": [], "total": 0, "page": 1, "per_page": per_page}
        except Exception as e:
            print_error(f"Erreur lors de la récupération de la liste: {e}")
            return {"extensions": [], "total": 0, "page": 1, "per_page": per_page}
    
    def get_extension(self, extension_id: str) -> Optional[Dict[str, Any]]:
        """Récupère les détails d'une extension"""
        try:
            response = requests.get(
                f"{self.registry_url}/api/registry/extensions/{extension_id}",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print_error(f"Erreur lors de la récupération de l'extension: {e}")
            return None
    
    def install_extension(
        self,
        extension_id: str,
        version: Optional[str] = None,
        user_id: Optional[str] = None,
        verify_signature: bool = True
    ) -> bool:
        """
        Installe une extension
        
        Args:
            extension_id: ID de l'extension
            version: Version spécifique (None pour latest)
            user_id: ID de l'utilisateur (pour vérifier la licence)
            verify_signature: Vérifier la signature avant installation
            
        Returns:
            True si l'installation a réussi
        """
        try:
            print_info(f"Installation de l'extension {extension_id}...")
            
            # Télécharger le bundle
            params = {}
            if version:
                params["version"] = version
            
            response = requests.get(
                f"{self.registry_url}/api/registry/extensions/{extension_id}/download",
                params=params,
                stream=True,
                timeout=30
            )
            response.raise_for_status()
            
            # Créer un fichier temporaire
            with tempfile.NamedTemporaryFile(delete=False, suffix='.kext') as tmp_file:
                tmp_path = tmp_file.name
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
            
            # Extraire et vérifier le manifest
            extract_dir = os.path.join(self.extensions_dir, extension_id)
            if version:
                extract_dir = os.path.join(extract_dir, version)
            else:
                extract_dir = os.path.join(extract_dir, "latest")
            
            os.makedirs(extract_dir, exist_ok=True)
            
            # Extraire le bundle
            if tmp_path.endswith('.zip') or tmp_path.endswith('.kext'):
                with zipfile.ZipFile(tmp_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
            
            # Chercher le manifest
            manifest_path = os.path.join(extract_dir, "extension.toml")
            if not os.path.exists(manifest_path):
                print_error("Manifest extension.toml non trouvé dans le bundle")
                os.remove(tmp_path)
                return False
            
            # Parser le manifest
            manifest = ManifestParser.parse(manifest_path)
            if not manifest:
                print_error("Erreur lors du parsing du manifest")
                os.remove(tmp_path)
                return False
            
            # Valider le manifest
            is_valid, errors = ManifestParser.validate(manifest)
            if not is_valid:
                print_error(f"Manifest invalide: {', '.join(errors)}")
                os.remove(tmp_path)
                return False
            
            # Vérifier la signature si demandé
            if verify_signature and manifest.signature and manifest.public_key:
                manifest_content = open(manifest_path, 'r', encoding='utf-8').read()
                if not self.signature_manager.verify_signature(
                    manifest_content,
                    manifest.signature,
                    manifest.public_key
                ):
                    print_error("Signature invalide - installation refusée")
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    os.remove(tmp_path)
                    return False
            
            # Vérifier la compatibilité avec KittySploit
            from core.config import Config
            try:
                kittysploit_version = Config.VERSION
                if manifest.compatibility:
                    from packaging import version as pkg_version
                    min_version = manifest.compatibility.kittysploit_min
                    max_version = manifest.compatibility.kittysploit_max
                    
                    if pkg_version.parse(kittysploit_version) < pkg_version.parse(min_version):
                        print_error(f"Version KittySploit {kittysploit_version} < {min_version} requise")
                        shutil.rmtree(extract_dir, ignore_errors=True)
                        os.remove(tmp_path)
                        return False
                    
                    if max_version and pkg_version.parse(kittysploit_version) > pkg_version.parse(max_version):
                        print_warning(f"Version KittySploit {kittysploit_version} > {max_version} supportée")
            except Exception as e:
                print_warning(f"Impossible de vérifier la compatibilité: {e}")
            
            # Générer le profil sandbox depuis les permissions du manifest
            sandbox_config = self._generate_sandbox_config(manifest)
            
            # Valider avec PolicyEngine si disponible
            try:
                from core.framework.utils.policy_engine import PolicyEngine, PolicyLevel
                
                # Déterminer le niveau de politique
                policy_level_map = {
                    "permissive": PolicyLevel.PERMISSIVE,
                    "standard": PolicyLevel.STANDARD,
                    "strict": PolicyLevel.STRICT,
                    "paranoid": PolicyLevel.PARANOID
                }
                policy_level = policy_level_map.get(
                    manifest.permissions.sandbox_level,
                    PolicyLevel.STANDARD
                )
                
                # Créer le PolicyEngine
                policy_engine = PolicyEngine(policy_level=policy_level)
                
                # Lire le code principal si entry_point est défini
                if manifest.entry_point:
                    entry_file = os.path.join(extract_dir, manifest.entry_point)
                    if os.path.exists(entry_file):
                        with open(entry_file, 'r', encoding='utf-8') as f:
                            entry_code = f.read()
                        
                        # Valider avec PolicyEngine
                        validation_result = policy_engine.validate_module(
                            module_path=f"extensions/{extension_id}/{manifest.entry_point}",
                            module_code=entry_code,
                            require_approval=False,  # Auto-approbation pour extensions signées
                            enable_sandbox=(policy_level in [PolicyLevel.STRICT, PolicyLevel.PARANOID])
                        )
                        
                        if not validation_result.get("valid", True):
                            print_warning("Avertissements de validation PolicyEngine:")
                            for warning in validation_result.get("warnings", []):
                                print_warning(f"  - {warning}")
                            
                            if validation_result.get("errors"):
                                print_error("Erreurs de validation PolicyEngine:")
                                for error in validation_result.get("errors", []):
                                    print_error(f"  - {error}")
                                # Ne pas bloquer, mais avertir
            except ImportError:
                print_warning("PolicyEngine non disponible - validation sandbox ignorée")
            except Exception as e:
                print_warning(f"Erreur lors de la validation PolicyEngine: {e}")
            
            # Sauvegarder la configuration sandbox
            sandbox_config_path = os.path.join(extract_dir, ".sandbox_config.json")
            try:
                import json
                with open(sandbox_config_path, 'w') as f:
                    json.dump(sandbox_config, f, indent=2)
            except Exception as e:
                print_warning(f"Impossible de sauvegarder la config sandbox: {e}")
            
            # Enregistrer les hooks/events/middlewares si déclarés
            self._register_extension_components(manifest, extract_dir)
            
            # Installation réussie
            os.remove(tmp_path)
            print_success(f"Extension {extension_id} v{manifest.version} installée avec succès")
            return True
            
        except Exception as e:
            print_error(f"Erreur lors de l'installation: {e}")
            return False
    
    def update_extension(self, extension_id: str, version: Optional[str] = None) -> bool:
        """Met à jour une extension vers une version plus récente"""
        # Désinstaller l'ancienne version
        old_dir = os.path.join(self.extensions_dir, extension_id)
        if os.path.exists(old_dir):
            shutil.rmtree(old_dir, ignore_errors=True)
        
        # Installer la nouvelle version
        return self.install_extension(extension_id, version=version)
    
    def remove_extension(self, extension_id: str) -> bool:
        """Supprime une extension installée"""
        try:
            ext_dir = os.path.join(self.extensions_dir, extension_id)
            if os.path.exists(ext_dir):
                shutil.rmtree(ext_dir, ignore_errors=True)
                print_success(f"Extension {extension_id} supprimée")
                return True
            else:
                print_warning(f"Extension {extension_id} non trouvée")
                return False
        except Exception as e:
            print_error(f"Erreur lors de la suppression: {e}")
            return False
    
    def list_installed_extensions(self) -> List[Dict[str, Any]]:
        """Liste les extensions installées localement"""
        installed = []
        
        if not os.path.exists(self.extensions_dir):
            return installed
        
        for ext_id in os.listdir(self.extensions_dir):
            ext_path = os.path.join(self.extensions_dir, ext_id)
            if not os.path.isdir(ext_path):
                continue
            
            # Chercher le manifest
            manifest_path = None
            for root, dirs, files in os.walk(ext_path):
                if "extension.toml" in files:
                    manifest_path = os.path.join(root, "extension.toml")
                    break
            
            if manifest_path:
                manifest = ManifestParser.parse(manifest_path)
                if manifest:
                    installed.append({
                        "id": manifest.id,
                        "name": manifest.name,
                        "version": manifest.version,
                        "type": manifest.extension_type.value,
                        "path": ext_path
                    })
        
        return installed
    
    def purchase_extension(self, extension_id: str, user_id: str, version: Optional[str] = None) -> bool:
        """Achète une extension payante"""
        try:
            data = {}
            if version:
                data["version"] = version
            
            response = requests.post(
                f"{self.registry_url}/api/registry/extensions/{extension_id}/purchase",
                json={"user_id": user_id, **data},
                timeout=10
            )
            response.raise_for_status()
            
            result = response.json()
            if result.get("success"):
                print_success(f"Extension {extension_id} achetée avec succès")
                return True
            else:
                print_error(result.get("error", "Erreur inconnue"))
                return False
        except Exception as e:
            print_error(f"Erreur lors de l'achat: {e}")
            return False
    
    def _generate_sandbox_config(self, manifest) -> Dict[str, Any]:
        """
        Génère une configuration sandbox depuis le manifest
        
        Args:
            manifest: ExtensionManifest
            
        Returns:
            Dict de configuration sandbox
        """
        config = {
            "allowed_imports": manifest.permissions.allowed_imports,
            "blocked_imports": manifest.permissions.blocked_imports,
            "sandbox_level": manifest.permissions.sandbox_level,
            "network_access": manifest.permissions.network_access,
            "database_access": manifest.permissions.database_access,
        }
        
        # Ajouter des restrictions selon le niveau
        if manifest.permissions.sandbox_level == "strict":
            config["max_cpu_percent"] = 80.0
            config["max_memory_mb"] = 512
            config["max_execution_time"] = 300
        elif manifest.permissions.sandbox_level == "paranoid":
            config["max_cpu_percent"] = 50.0
            config["max_memory_mb"] = 256
            config["max_execution_time"] = 180
        
        return config
    
    def _register_extension_components(self, manifest, extract_dir: str):
        """
        Enregistre les hooks/events/middlewares déclarés dans le manifest
        
        Args:
            manifest: ExtensionManifest
            extract_dir: Répertoire d'extraction de l'extension
        """
        try:
            # Cette fonction sera appelée lors du chargement du framework
            # pour enregistrer automatiquement les composants déclarés
            
            # Créer un fichier de métadonnées pour le chargement automatique
            metadata_path = os.path.join(extract_dir, ".extension_metadata.json")
            import json
            
            metadata = {
                "id": manifest.id,
                "version": manifest.version,
                "type": manifest.extension_type.value,
                "entry_point": manifest.entry_point,
                "hooks": manifest.permissions.hooks,
                "events": manifest.permissions.events,
                "middlewares": manifest.permissions.middlewares,
                "sandbox_config": self._generate_sandbox_config(manifest)
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print_info(f"Composants enregistrés: {len(manifest.permissions.hooks)} hooks, "
                      f"{len(manifest.permissions.events)} events, "
                      f"{len(manifest.permissions.middlewares)} middlewares")
        except Exception as e:
            print_warning(f"Erreur lors de l'enregistrement des composants: {e}")

