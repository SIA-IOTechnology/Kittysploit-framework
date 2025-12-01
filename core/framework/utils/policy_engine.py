#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Policy Engine - Moteur de politique de sécurité pour la validation et l'approbation des modules
Transforme ModuleValidator en un système complet de sécurité by design avec :
- AST statique avancé
- Sandbox dynamique
- Signatures cryptographiques
- Store de modules signé
- Graphe de dépendances
- Chaîne d'approbation/gating
- Mode différentiel (déclaration vs exécution)
"""

import os
import ast
import hashlib
import json
import time
from typing import Dict, List, Any, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
import importlib.util
import sys
import traceback
from pathlib import Path

from core.encryption_manager import EncryptionManager
from core.output_handler import print_info, print_warning, print_error, print_success, print_status


class PolicyLevel(Enum):
    """Niveaux de politique de sécurité"""
    PERMISSIVE = "permissive"  # Validation minimale
    STANDARD = "standard"      # Validation standard
    STRICT = "strict"          # Validation stricte
    PARANOID = "paranoid"      # Validation maximale avec sandbox obligatoire


class ApprovalStatus(Enum):
    """Statut d'approbation d'un module"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"
    AUTO_APPROVED = "auto_approved"  # Auto-approuvé par signature valide


@dataclass
class ModuleSignature:
    """Signature cryptographique d'un module"""
    module_hash: str
    signature: str
    signer: str
    timestamp: float
    algorithm: str = "ECDSA-SHA256"
    certificate_chain: List[str] = field(default_factory=list)


@dataclass
class ModuleManifest:
    """Manifeste d'un module avec métadonnées de sécurité"""
    module_path: str
    module_hash: str
    declared_capabilities: List[str]  # Ce que le module déclare faire
    declared_dependencies: List[str]
    declared_restrictions: List[str]  # Restrictions auto-déclarées
    signature: Optional[ModuleSignature] = None
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_timestamp: Optional[float] = None
    approver: Optional[str] = None
    risk_score: float = 0.0  # Score de risque (0-100)
    ast_analysis: Dict[str, Any] = field(default_factory=dict)
    sandbox_results: Optional[Dict[str, Any]] = None
    differential_analysis: Optional[Dict[str, Any]] = None


@dataclass
class DependencyNode:
    """Nœud dans le graphe de dépendances"""
    module_path: str
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)
    version: Optional[str] = None
    signature: Optional[ModuleSignature] = None


class PolicyEngine:
    """Moteur de politique de sécurité pour les modules"""
    
    def __init__(
        self,
        encryption_manager: Optional[EncryptionManager] = None,
        policy_level: PolicyLevel = PolicyLevel.STANDARD,
        store_path: Optional[str] = None
    ):
        """
        Initialise le moteur de politique
        
        Args:
            encryption_manager: Instance d'EncryptionManager pour les signatures
            policy_level: Niveau de politique de sécurité
            store_path: Chemin vers le store de modules signés
        """
        self.encryption_manager = encryption_manager or EncryptionManager()
        self.policy_level = policy_level
        self.store_path = store_path or os.path.expanduser("~/.kittysploit/module_store")
        os.makedirs(self.store_path, exist_ok=True)
        
        # Composants du moteur (imports différés pour éviter les dépendances circulaires)
        self.ast_analyzer = None
        self.sandbox_executor = None
        self.signature_manager = None
        self.dependency_graph = None
        self.approval_chain = None
        self.differential_analyzer = None
        self._initialize_components(policy_level)
        
        # Cache des manifestes
        self.manifest_cache: Dict[str, ModuleManifest] = {}
        self.manifest_file = os.path.join(self.store_path, "manifests.json")
        self._load_manifests()
    
    def validate_module(
        self,
        module_path: str,
        module_code: str,
        require_approval: bool = True,
        enable_sandbox: Optional[bool] = None,
        enable_differential: bool = False
    ) -> Dict[str, Any]:
        """
        Valide un module avec toutes les couches de sécurité
        
        Args:
            module_path: Chemin du module
            module_code: Code source du module
            require_approval: Exiger une approbation avant exécution
            enable_sandbox: Activer le sandbox (None = selon policy_level)
            enable_differential: Activer l'analyse différentielle
            
        Returns:
            Dictionnaire avec les résultats de validation
        """
        result = {
            "valid": False,
            "module_path": module_path,
            "errors": [],
            "warnings": [],
            "approval_required": False,
            "approval_status": None,
            "risk_score": 0.0,
            "ast_analysis": {},
            "sandbox_results": None,
            "signature_valid": False,
            "dependencies": [],
            "differential_analysis": None
        }
        
        # 1. Calcul du hash du module
        module_hash = self._calculate_module_hash(module_code)
        result["module_hash"] = module_hash
        
        # 2. Vérifier si le module existe déjà dans le store
        existing_manifest = self._get_manifest(module_path)
        if existing_manifest and existing_manifest.module_hash == module_hash:
            # Module inchangé, réutiliser l'analyse
            if existing_manifest.approval_status == ApprovalStatus.APPROVED:
                result["valid"] = True
                result["approval_status"] = existing_manifest.approval_status.value
                result["risk_score"] = existing_manifest.risk_score
                return result
        
        # 3. Analyse AST statique
        try:
            ast_result = self.ast_analyzer.analyze(module_code, module_path)
            result["ast_analysis"] = ast_result
            result["warnings"].extend(ast_result.get("warnings", []))
            result["errors"].extend(ast_result.get("errors", []))
            
            if not ast_result.get("valid", False):
                return result
        except Exception as e:
            result["errors"].append(f"Erreur d'analyse AST: {e}")
            return result
        
        # 4. Extraction des déclarations du module
        declared_capabilities = ast_result.get("declared_capabilities", [])
        declared_dependencies = ast_result.get("dependencies", [])
        declared_restrictions = ast_result.get("declared_restrictions", [])
        
        # 5. Vérification des signatures cryptographiques
        signature_valid = False
        signature = None
        if existing_manifest and existing_manifest.signature:
            signature_valid = self.signature_manager.verify_signature(
                module_code,
                existing_manifest.signature
            )
            if signature_valid:
                result["signature_valid"] = True
                signature = existing_manifest.signature
        
        # 6. Analyse du graphe de dépendances
        dependency_issues = self.dependency_graph.validate_dependencies(
            module_path,
            declared_dependencies
        )
        if dependency_issues:
            result["warnings"].extend(dependency_issues)
        result["dependencies"] = declared_dependencies
        
        # 7. Sandbox dynamique (si requis)
        sandbox_enabled = enable_sandbox
        if sandbox_enabled is None:
            sandbox_enabled = self.policy_level in [PolicyLevel.STRICT, PolicyLevel.PARANOID]
        
        if sandbox_enabled:
            try:
                sandbox_result = self.sandbox_executor.execute_safely(
                    module_code,
                    module_path,
                    timeout=30
                )
                result["sandbox_results"] = sandbox_result
                if not sandbox_result.get("safe", True):
                    result["errors"].append("Module non sécurisé selon le sandbox")
                    result["warnings"].extend(sandbox_result.get("warnings", []))
            except Exception as e:
                result["warnings"].append(f"Erreur lors du sandbox: {e}")
        
        # 8. Analyse différentielle (si activée)
        if enable_differential:
            try:
                diff_result = self.differential_analyzer.analyze(
                    module_code,
                    declared_capabilities,
                    declared_restrictions
                )
                result["differential_analysis"] = diff_result
                if diff_result.get("mismatch", False):
                    result["warnings"].append(
                        "Décalage détecté entre déclarations et implémentation"
                    )
            except Exception as e:
                result["warnings"].append(f"Erreur lors de l'analyse différentielle: {e}")
        
        # 9. Calcul du score de risque
        risk_score = self._calculate_risk_score(
            ast_result,
            result.get("sandbox_results"),
            signature_valid,
            declared_capabilities
        )
        result["risk_score"] = risk_score
        
        # 10. Vérification de l'approbation
        if require_approval:
            approval_status = self.approval_chain.get_approval_status(module_path, module_hash)
            result["approval_status"] = approval_status.value if approval_status else None
            result["approval_required"] = approval_status != ApprovalStatus.APPROVED
            
            if approval_status == ApprovalStatus.REJECTED:
                result["errors"].append("Module rejeté par la chaîne d'approbation")
                return result
            elif approval_status == ApprovalStatus.REVOKED:
                result["errors"].append("Module révoqué")
                return result
        
        # 11. Création/mise à jour du manifeste
        manifest = ModuleManifest(
            module_path=module_path,
            module_hash=module_hash,
            declared_capabilities=declared_capabilities,
            declared_dependencies=declared_dependencies,
            declared_restrictions=declared_restrictions,
            signature=signature,
            approval_status=approval_status if require_approval else ApprovalStatus.AUTO_APPROVED,
            risk_score=risk_score,
            ast_analysis=ast_result,
            sandbox_results=result.get("sandbox_results"),
            differential_analysis=result.get("differential_analysis")
        )
        self._save_manifest(manifest)
        
        # 12. Mise à jour du graphe de dépendances
        self.dependency_graph.add_module(module_path, declared_dependencies)
        
        # Validation finale
        result["valid"] = len(result["errors"]) == 0
        
        return result
    
    def approve_module(
        self,
        module_path: str,
        approver: str,
        reason: Optional[str] = None
    ) -> bool:
        """
        Approuve un module manuellement
        
        Args:
            module_path: Chemin du module
            approver: Identité de l'approbateur
            reason: Raison de l'approbation
            
        Returns:
            True si l'approbation a réussi
        """
        return self.approval_chain.approve_module(
            module_path,
            approver,
            reason
        )
    
    def revoke_module(self, module_path: str, reason: str) -> bool:
        """
        Révoque l'approbation d'un module
        
        Args:
            module_path: Chemin du module
            reason: Raison de la révocation
            
        Returns:
            True si la révocation a réussi
        """
        return self.approval_chain.revoke_module(module_path, reason)
    
    def sign_module(
        self,
        module_path: str,
        module_code: str,
        signer: str
    ) -> Optional[ModuleSignature]:
        """
        Signe un module cryptographiquement
        
        Args:
            module_path: Chemin du module
            module_code: Code source du module
            signer: Identité du signataire
            
        Returns:
            Signature du module ou None en cas d'erreur
        """
        module_hash = self._calculate_module_hash(module_code)
        signature = self.signature_manager.sign_module(module_code, signer)
        
        if signature:
            # Mettre à jour le manifeste
            manifest = self._get_manifest(module_path)
            if manifest:
                manifest.signature = signature
                self._save_manifest(manifest)
        
        return signature
    
    def get_dependency_graph(self) -> Dict[str, Any]:
        """
        Retourne le graphe de dépendances complet
        
        Returns:
            Représentation du graphe de dépendances
        """
        return self.dependency_graph.get_graph()
    
    def _calculate_module_hash(self, module_code: str) -> str:
        """Calcule le hash SHA256 d'un module"""
        return hashlib.sha256(module_code.encode('utf-8')).hexdigest()
    
    def _calculate_risk_score(
        self,
        ast_result: Dict[str, Any],
        sandbox_results: Optional[Dict[str, Any]],
        signature_valid: bool,
        declared_capabilities: List[str]
    ) -> float:
        """
        Calcule un score de risque (0-100)
        
        Returns:
            Score de risque entre 0 et 100
        """
        score = 0.0
        
        # Facteurs de risque AST
        dangerous_patterns = ast_result.get("dangerous_patterns", [])
        score += len(dangerous_patterns) * 5
        
        # Facteurs de risque sandbox
        if sandbox_results:
            if not sandbox_results.get("safe", True):
                score += 20
            suspicious_actions = sandbox_results.get("suspicious_actions", [])
            score += len(suspicious_actions) * 3
        
        # Signature valide réduit le risque
        if signature_valid:
            score -= 15
        
        # Capabilities dangereuses
        high_risk_capabilities = ["file_write", "network_connect", "system_exec", "code_exec"]
        for cap in declared_capabilities:
            if cap in high_risk_capabilities:
                score += 10
        
        return max(0.0, min(100.0, score))
    
    def _get_manifest(self, module_path: str) -> Optional[ModuleManifest]:
        """Récupère le manifeste d'un module"""
        if module_path in self.manifest_cache:
            return self.manifest_cache[module_path]
        return None
    
    def _save_manifest(self, manifest: ModuleManifest):
        """Sauvegarde un manifeste"""
        self.manifest_cache[manifest.module_path] = manifest
        self._persist_manifests()
    
    def _load_manifests(self):
        """Charge les manifestes depuis le disque"""
        if not os.path.exists(self.manifest_file):
            return
        
        try:
            with open(self.manifest_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for path, manifest_data in data.items():
                    # Reconstruire le manifeste depuis les données JSON
                    manifest = self._manifest_from_dict(manifest_data)
                    self.manifest_cache[path] = manifest
        except Exception as e:
            print_warning(f"Erreur lors du chargement des manifestes: {e}")
    
    def _persist_manifests(self):
        """Persiste les manifestes sur le disque"""
        try:
            data = {}
            for path, manifest in self.manifest_cache.items():
                data[path] = self._manifest_to_dict(manifest)
            
            with open(self.manifest_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print_error(f"Erreur lors de la sauvegarde des manifestes: {e}")
    
    def _manifest_to_dict(self, manifest: ModuleManifest) -> Dict[str, Any]:
        """Convertit un manifeste en dictionnaire"""
        data = asdict(manifest)
        if manifest.signature:
            data["signature"] = asdict(manifest.signature)
        if manifest.approval_status:
            data["approval_status"] = manifest.approval_status.value
        return data
    
    def _manifest_from_dict(self, data: Dict[str, Any]) -> ModuleManifest:
        """Reconstruit un manifeste depuis un dictionnaire"""
        if "approval_status" in data:
            data["approval_status"] = ApprovalStatus(data["approval_status"])
        if "signature" in data and data["signature"]:
            sig_data = data["signature"]
            data["signature"] = ModuleSignature(**sig_data)
        return ModuleManifest(**data)
    
    def _initialize_components(self, policy_level: PolicyLevel):
        """Initialise les composants du moteur de politique"""
        try:
            from core.framework.utils.ast_analyzer import ASTAnalyzer
            from core.framework.utils.sandbox_executor import SandboxExecutor
            from core.framework.utils.signature_manager import SignatureManager
            from core.framework.utils.dependency_graph import DependencyGraph
            from core.framework.utils.approval_chain import ApprovalChain
            from core.framework.utils.differential_analyzer import DifferentialAnalyzer
            
            self.ast_analyzer = ASTAnalyzer(policy_level=policy_level)
            self.sandbox_executor = SandboxExecutor()
            self.signature_manager = SignatureManager(encryption_manager=self.encryption_manager)
            self.dependency_graph = DependencyGraph()
            self.approval_chain = ApprovalChain(store_path=self.store_path)
            self.differential_analyzer = DifferentialAnalyzer()
        except ImportError as e:
            print_warning(f"Impossible de charger certains composants du PolicyEngine: {e}")
            # Créer des stubs pour éviter les erreurs
            class Stub:
                def analyze(self, *args, **kwargs): return {"valid": True, "errors": [], "warnings": []}
                def execute_safely(self, *args, **kwargs): return {"safe": True}
                def sign_module(self, *args, **kwargs): return None
                def verify_signature(self, *args, **kwargs): return False
                def add_module(self, *args, **kwargs): pass
                def validate_dependencies(self, *args, **kwargs): return []
                def get_graph(self): return {}
                def get_approval_status(self, *args, **kwargs): 
                    return ApprovalStatus.PENDING
                def analyze(self, *args, **kwargs): return {"mismatch": False}
            
            self.ast_analyzer = Stub()
            self.sandbox_executor = Stub()
            self.signature_manager = Stub()
            self.dependency_graph = Stub()
            self.approval_chain = Stub()
            self.differential_analyzer = Stub()

