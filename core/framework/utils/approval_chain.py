#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Approval Chain - Chaîne d'approbation pour les modules
Système de gating avant exécution pour environnements sensibles
"""

import os
import json
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from core.framework.utils.policy_engine import ApprovalStatus
from core.output_handler import print_info, print_warning, print_error


class ApprovalRule(Enum):
    """Règles d'approbation"""
    AUTO_APPROVE_SIGNED = "auto_approve_signed"  # Auto-approuver les modules signés
    REQUIRE_MANUAL = "require_manual"            # Exiger approbation manuelle
    REQUIRE_MULTI_PARTY = "require_multi_party"  # Exiger plusieurs approbateurs
    BLOCK_HIGH_RISK = "block_high_risk"          # Bloquer les modules à haut risque


@dataclass
class ApprovalRecord:
    """Enregistrement d'approbation"""
    module_path: str
    module_hash: str
    status: ApprovalStatus
    approver: Optional[str]
    timestamp: float
    reason: Optional[str] = None
    risk_score: float = 0.0
    signature_valid: bool = False


class ApprovalChain:
    """Chaîne d'approbation pour les modules"""
    
    def __init__(self, store_path: str):
        """
        Initialise la chaîne d'approbation
        
        Args:
            store_path: Chemin vers le store
        """
        self.store_path = store_path
        self.approvals_file = os.path.join(store_path, "approvals.json")
        self.approvals: Dict[str, ApprovalRecord] = {}
        self.rules: List[ApprovalRule] = [ApprovalRule.AUTO_APPROVE_SIGNED]
        self._load_approvals()
    
    def get_approval_status(
        self,
        module_path: str,
        module_hash: str,
        risk_score: float = 0.0,
        signature_valid: bool = False
    ) -> ApprovalStatus:
        """
        Récupère le statut d'approbation d'un module
        
        Args:
            module_path: Chemin du module
            module_hash: Hash du module
            risk_score: Score de risque
            signature_valid: Si la signature est valide
            
        Returns:
            Statut d'approbation
        """
        # Vérifier si une approbation existe
        approval_key = f"{module_path}:{module_hash}"
        if approval_key in self.approvals:
            record = self.approvals[approval_key]
            return record.status
        
        # Appliquer les règles d'auto-approbation
        if ApprovalRule.AUTO_APPROVE_SIGNED in self.rules:
            if signature_valid:
                # Auto-approuver les modules signés
                self._auto_approve(module_path, module_hash, risk_score, signature_valid)
                return ApprovalStatus.AUTO_APPROVED
        
        # Bloquer les modules à haut risque
        if ApprovalRule.BLOCK_HIGH_RISK in self.rules:
            if risk_score > 70.0:
                return ApprovalStatus.REJECTED
        
        # Par défaut, nécessite une approbation manuelle
        return ApprovalStatus.PENDING
    
    def approve_module(
        self,
        module_path: str,
        approver: str,
        reason: Optional[str] = None,
        module_hash: Optional[str] = None
    ) -> bool:
        """
        Approuve un module manuellement
        
        Args:
            module_path: Chemin du module
            approver: Identité de l'approbateur
            reason: Raison de l'approbation
            module_hash: Hash du module (optionnel)
            
        Returns:
            True si l'approbation a réussi
        """
        try:
            # Si le hash n'est pas fourni, utiliser le dernier connu
            if not module_hash:
                # Chercher le dernier hash pour ce module
                for key, record in self.approvals.items():
                    if key.startswith(f"{module_path}:"):
                        module_hash = record.module_hash
                        break
            
            if not module_hash:
                print_error("Hash du module requis pour l'approbation")
                return False
            
            approval_key = f"{module_path}:{module_hash}"
            
            record = ApprovalRecord(
                module_path=module_path,
                module_hash=module_hash,
                status=ApprovalStatus.APPROVED,
                approver=approver,
                timestamp=datetime.now().timestamp(),
                reason=reason
            )
            
            self.approvals[approval_key] = record
            self._persist_approvals()
            
            print_info(f"Module {module_path} approuvé par {approver}")
            return True
            
        except Exception as e:
            print_error(f"Erreur lors de l'approbation: {e}")
            return False
    
    def revoke_module(
        self,
        module_path: str,
        reason: str,
        module_hash: Optional[str] = None
    ) -> bool:
        """
        Révoque l'approbation d'un module
        
        Args:
            module_path: Chemin du module
            reason: Raison de la révocation
            module_hash: Hash du module (optionnel)
            
        Returns:
            True si la révocation a réussi
        """
        try:
            # Trouver tous les enregistrements pour ce module
            keys_to_revoke = []
            for key, record in self.approvals.items():
                if key.startswith(f"{module_path}:") and (
                    not module_hash or record.module_hash == module_hash
                ):
                    keys_to_revoke.append(key)
            
            if not keys_to_revoke:
                print_warning(f"Aucune approbation trouvée pour {module_path}")
                return False
            
            # Révoquer tous les enregistrements
            for key in keys_to_revoke:
                record = self.approvals[key]
                record.status = ApprovalStatus.REVOKED
                record.reason = reason
                record.timestamp = datetime.now().timestamp()
            
            self._persist_approvals()
            print_info(f"Module {module_path} révoqué: {reason}")
            return True
            
        except Exception as e:
            print_error(f"Erreur lors de la révocation: {e}")
            return False
    
    def reject_module(
        self,
        module_path: str,
        reason: str,
        module_hash: Optional[str] = None
    ) -> bool:
        """
        Rejette un module
        
        Args:
            module_path: Chemin du module
            reason: Raison du rejet
            module_hash: Hash du module (optionnel)
            
        Returns:
            True si le rejet a réussi
        """
        try:
            if not module_hash:
                # Utiliser un hash générique pour le rejet
                module_hash = "rejected"
            
            approval_key = f"{module_path}:{module_hash}"
            
            record = ApprovalRecord(
                module_path=module_path,
                module_hash=module_hash,
                status=ApprovalStatus.REJECTED,
                approver=None,
                timestamp=datetime.now().timestamp(),
                reason=reason
            )
            
            self.approvals[approval_key] = record
            self._persist_approvals()
            
            print_info(f"Module {module_path} rejeté: {reason}")
            return True
            
        except Exception as e:
            print_error(f"Erreur lors du rejet: {e}")
            return False
    
    def _auto_approve(
        self,
        module_path: str,
        module_hash: str,
        risk_score: float,
        signature_valid: bool
    ):
        """Auto-approuve un module"""
        approval_key = f"{module_path}:{module_hash}"
        
        record = ApprovalRecord(
            module_path=module_path,
            module_hash=module_hash,
            status=ApprovalStatus.AUTO_APPROVED,
            approver="system",
            timestamp=datetime.now().timestamp(),
            reason="Auto-approuvé: signature valide",
            risk_score=risk_score,
            signature_valid=signature_valid
        )
        
        self.approvals[approval_key] = record
        self._persist_approvals()
    
    def _load_approvals(self):
        """Charge les approbations depuis le disque"""
        if not os.path.exists(self.approvals_file):
            return
        
        try:
            with open(self.approvals_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for key, record_data in data.items():
                    record = ApprovalRecord(**record_data)
                    # Convertir le statut string en enum
                    if isinstance(record.status, str):
                        record.status = ApprovalStatus(record.status)
                    self.approvals[key] = record
        except Exception as e:
            print_warning(f"Erreur lors du chargement des approbations: {e}")
    
    def _persist_approvals(self):
        """Persiste les approbations sur le disque"""
        try:
            data = {}
            for key, record in self.approvals.items():
                record_dict = asdict(record)
                record_dict["status"] = record.status.value
                data[key] = record_dict
            
            with open(self.approvals_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print_error(f"Erreur lors de la sauvegarde des approbations: {e}")

