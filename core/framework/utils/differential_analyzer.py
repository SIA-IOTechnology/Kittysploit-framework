#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Differential Analyzer - Analyse différentielle pour comparer déclarations vs exécution
Détecte les abus et comportements non déclarés
"""

import ast
from typing import Dict, List, Any, Set, Optional
from core.framework.utils.ast_analyzer import ASTAnalyzer


class DifferentialAnalyzer:
    """Analyseur différentiel pour détecter les écarts entre déclarations et implémentation"""
    
    def __init__(self):
        """Initialise l'analyseur différentiel"""
        self.ast_analyzer = ASTAnalyzer()
    
    def analyze(
        self,
        module_code: str,
        declared_capabilities: List[str],
        declared_restrictions: List[str]
    ) -> Dict[str, Any]:
        """
        Analyse les différences entre déclarations et implémentation
        
        Args:
            module_code: Code source du module
            declared_capabilities: Capacités déclarées
            declared_restrictions: Restrictions déclarées
            
        Returns:
            Résultats de l'analyse différentielle
        """
        result = {
            "mismatch": False,
            "undeclared_capabilities": [],
            "violated_restrictions": [],
            "missing_declarations": [],
            "warnings": []
        }
        
        try:
            # Analyser le code pour détecter les capacités réelles
            ast_result = self.ast_analyzer.analyze(module_code, "module")
            actual_capabilities = self._extract_actual_capabilities(ast_result)
            
            # Comparer avec les déclarations
            declared_set = set(declared_capabilities)
            actual_set = set(actual_capabilities)
            
            # Capacités non déclarées
            undeclared = actual_set - declared_set
            if undeclared:
                result["undeclared_capabilities"] = list(undeclared)
                result["mismatch"] = True
                result["warnings"].append(
                    f"Capacités non déclarées détectées: {', '.join(undeclared)}"
                )
            
            # Capacités déclarées mais non utilisées (moins critique)
            unused = declared_set - actual_set
            if unused:
                result["warnings"].append(
                    f"Capacités déclarées mais non utilisées: {', '.join(unused)}"
                )
            
            # Vérifier les restrictions
            violated = self._check_restrictions(ast_result, declared_restrictions)
            if violated:
                result["violated_restrictions"] = violated
                result["mismatch"] = True
                result["warnings"].append(
                    f"Restrictions violées: {', '.join(violated)}"
                )
            
        except Exception as e:
            result["warnings"].append(f"Erreur lors de l'analyse différentielle: {e}")
        
        return result
    
    def _extract_actual_capabilities(self, ast_result: Dict[str, Any]) -> List[str]:
        """
        Extrait les capacités réelles du code
        
        Args:
            ast_result: Résultats de l'analyse AST
            
        Returns:
            Liste des capacités détectées
        """
        capabilities = []
        
        # Analyser les imports pour détecter les capacités
        imports = ast_result.get("dependencies", [])
        
        if any("socket" in imp or "urllib" in imp or "requests" in imp for imp in imports):
            capabilities.append("network_connect")
        
        if any("os" in imp or "shutil" in imp for imp in imports):
            capabilities.append("file_operations")
        
        if any("subprocess" in imp or "os.system" in imp for imp in imports):
            capabilities.append("system_exec")
        
        if any("eval" in imp or "exec" in imp or "compile" in imp for imp in imports):
            capabilities.append("code_exec")
        
        # Analyser les patterns dangereux
        dangerous_patterns = ast_result.get("dangerous_patterns", [])
        for pattern in dangerous_patterns:
            pattern_type = pattern.get("type", "")
            if pattern_type == "dangerous_call":
                func = pattern.get("function", "")
                if func in ["eval", "exec", "compile"]:
                    capabilities.append("code_exec")
            elif pattern_type == "dangerous_method_call":
                method = pattern.get("method", "")
                if "socket" in method or "urllib" in method:
                    capabilities.append("network_connect")
                elif "os.remove" in method or "shutil" in method:
                    capabilities.append("file_delete")
                elif "os.system" in method or "subprocess" in method:
                    capabilities.append("system_exec")
        
        return list(set(capabilities))
    
    def _check_restrictions(
        self,
        ast_result: Dict[str, Any],
        declared_restrictions: List[str]
    ) -> List[str]:
        """
        Vérifie si les restrictions déclarées sont respectées
        
        Args:
            ast_result: Résultats de l'analyse AST
            declared_restrictions: Restrictions déclarées
            
        Returns:
            Liste des restrictions violées
        """
        violated = []
        
        restrictions_map = {
            "no_network": ["network_connect"],
            "no_file_write": ["file_write", "file_delete"],
            "no_system_exec": ["system_exec"],
            "no_code_exec": ["code_exec"],
            "read_only": ["file_write", "file_delete", "file_create"]
        }
        
        # Extraire les capacités réelles
        actual_capabilities = self._extract_actual_capabilities(ast_result)
        actual_set = set(actual_capabilities)
        
        # Vérifier chaque restriction
        for restriction in declared_restrictions:
            if restriction in restrictions_map:
                forbidden_caps = set(restrictions_map[restriction])
                if actual_set & forbidden_caps:
                    violated.append(restriction)
        
        return violated

