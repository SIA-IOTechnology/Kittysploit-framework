#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AST Analyzer - Analyseur statique avancé pour détecter les patterns dangereux
"""

import ast
import re
from typing import Dict, List, Any, Set, Optional
from enum import Enum
from core.framework.utils.policy_engine import PolicyLevel


class RiskLevel(Enum):
    """Niveaux de risque"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ASTAnalyzer:
    """Analyseur AST statique pour détecter les patterns dangereux"""
    
    # Patterns dangereux à détecter
    DANGEROUS_IMPORTS = {
        'os.system', 'os.popen', 'os.exec', 'subprocess', 'eval', 'exec',
        'compile', '__import__', 'importlib', 'ctypes', 'pickle', 'marshal'
    }
    
    DANGEROUS_FUNCTIONS = {
        'eval', 'exec', 'compile', '__import__', 'open', 'file',
        'input', 'raw_input', 'execfile', 'reload'
    }
    
    DANGEROUS_ATTRIBUTES = {
        '__builtins__', '__globals__', '__dict__', '__code__', '__class__'
    }
    
    NETWORK_OPERATIONS = {
        'socket', 'urllib', 'requests', 'httplib', 'ftplib', 'smtplib'
    }
    
    FILE_OPERATIONS = {
        'open', 'file', 'os.remove', 'os.unlink', 'shutil', 'tempfile'
    }
    
    def __init__(self, policy_level: PolicyLevel = PolicyLevel.STANDARD):
        """
        Initialise l'analyseur AST
        
        Args:
            policy_level: Niveau de politique de sécurité
        """
        self.policy_level = policy_level
        self.visitor = SecurityASTVisitor(self)
    
    def analyze(self, code: str, module_path: str) -> Dict[str, Any]:
        """
        Analyse le code source avec l'AST
        
        Args:
            code: Code source à analyser
            module_path: Chemin du module
            
        Returns:
            Résultats de l'analyse
        """
        result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "dangerous_patterns": [],
            "declared_capabilities": [],
            "dependencies": [],
            "declared_restrictions": [],
            "risk_factors": []
        }
        
        try:
            # Parse AST
            tree = ast.parse(code)
            
            # Visiter l'AST
            self.visitor.reset()
            self.visitor.visit(tree)
            
            # Collecter les résultats
            result["dangerous_patterns"] = self.visitor.dangerous_patterns
            result["dependencies"] = list(self.visitor.imports)
            result["declared_capabilities"] = self.visitor.declared_capabilities
            result["declared_restrictions"] = self.visitor.declared_restrictions
            result["risk_factors"] = self.visitor.risk_factors
            
            # Vérifier les patterns dangereux selon le niveau de politique
            if self.policy_level in [PolicyLevel.STRICT, PolicyLevel.PARANOID]:
                for pattern in self.visitor.dangerous_patterns:
                    if pattern["risk"] in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                        result["errors"].append(
                            f"Pattern dangereux détecté: {pattern['description']}"
                        )
                        result["valid"] = False
            
            # Vérifier la structure du module
            if not self.visitor.has_module_class:
                result["errors"].append("Module doit définir une classe 'Module'")
                result["valid"] = False
            
            if not self.visitor.has_run_method:
                result["errors"].append("Module doit définir une méthode 'run()'")
                result["valid"] = False
            
            if not self.visitor.has_info:
                result["warnings"].append("Module devrait définir '__info__'")
            
            # Analyser les imports
            for imp in self.visitor.imports:
                if any(dangerous in imp for dangerous in self.DANGEROUS_IMPORTS):
                    risk = RiskLevel.HIGH if self.policy_level == PolicyLevel.PARANOID else RiskLevel.MEDIUM
                    result["dangerous_patterns"].append({
                        "type": "dangerous_import",
                        "description": f"Import dangereux: {imp}",
                        "risk": risk.value,
                        "location": imp
                    })
                    if self.policy_level == PolicyLevel.PARANOID:
                        result["warnings"].append(f"Import potentiellement dangereux: {imp}")
            
        except SyntaxError as e:
            result["valid"] = False
            result["errors"].append(f"Erreur de syntaxe: {e}")
        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Erreur d'analyse: {e}")
        
        return result


class SecurityASTVisitor(ast.NodeVisitor):
    """Visiteur AST pour détecter les patterns de sécurité"""
    
    def __init__(self, analyzer: ASTAnalyzer):
        self.analyzer = analyzer
        self.reset()
    
    def reset(self):
        """Réinitialise l'état du visiteur"""
        self.dangerous_patterns: List[Dict[str, Any]] = []
        self.imports: Set[str] = set()
        self.declared_capabilities: List[str] = []
        self.declared_restrictions: List[str] = []
        self.risk_factors: List[str] = []
        self.has_module_class = False
        self.has_run_method = False
        self.has_info = False
    
    def visit_Import(self, node: ast.Import):
        """Visite les imports"""
        for alias in node.names:
            self.imports.add(alias.name)
            if alias.asname:
                self.imports.add(f"{alias.name} as {alias.asname}")
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Visite les imports from"""
        if node.module:
            for alias in node.names:
                full_import = f"{node.module}.{alias.name}"
                self.imports.add(full_import)
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Visite les définitions de classe"""
        if node.name == "Module":
            self.has_module_class = True
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visite les définitions de fonction"""
        if node.name == "run":
            self.has_run_method = True
        
        # Détecter les appels dangereux dans les fonctions
        self._check_dangerous_calls(node)
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Visite les appels de fonction"""
        # Détecter eval, exec, etc.
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.analyzer.DANGEROUS_FUNCTIONS:
                self.dangerous_patterns.append({
                    "type": "dangerous_call",
                    "description": f"Appel à fonction dangereuse: {func_name}",
                    "risk": RiskLevel.CRITICAL.value,
                    "function": func_name
                })
        
        # Détecter les appels à des méthodes dangereuses
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                attr_name = node.func.attr
                full_name = f"{module_name}.{attr_name}"
                
                if full_name in self.analyzer.DANGEROUS_IMPORTS:
                    self.dangerous_patterns.append({
                        "type": "dangerous_method_call",
                        "description": f"Appel à méthode dangereuse: {full_name}",
                        "risk": RiskLevel.HIGH.value,
                        "method": full_name
                    })
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Visite les assignations"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                # Détecter __info__
                if target.id == "__info__":
                    self.has_info = True
                    # Extraire les capacités déclarées
                    if isinstance(node.value, ast.Dict):
                        self._extract_info_dict(node.value)
        
        self.generic_visit(node)
    
    def _extract_info_dict(self, node: ast.Dict):
        """Extrait les informations du dictionnaire __info__"""
        for key_node, value_node in zip(node.keys, node.values):
                if isinstance(key_node, ast.Str):
                    key = key_node.s
                elif isinstance(key_node, ast.Constant):
                    key = key_node.value
                else:
                    continue
                
                if key == "capabilities" and isinstance(value_node, (ast.List, ast.Tuple)):
                    for item in value_node.elts:
                        if isinstance(item, ast.Str):
                            cap = item.s
                            self.declared_capabilities.append(str(cap))
                        elif isinstance(item, ast.Constant):
                            cap = item.value
                            self.declared_capabilities.append(str(cap))
                
                elif key == "dependencies" and isinstance(value_node, (ast.List, ast.Tuple)):
                    for item in value_node.elts:
                        if isinstance(item, ast.Str):
                            dep = item.s
                            # Déjà géré par visit_Import
                        elif isinstance(item, ast.Constant):
                            dep = item.value
                            # Déjà géré par visit_Import
                
                elif key == "restrictions" and isinstance(value_node, (ast.List, ast.Tuple)):
                    for item in value_node.elts:
                        if isinstance(item, ast.Str):
                            restriction = item.s
                            self.declared_restrictions.append(str(restriction))
                        elif isinstance(item, ast.Constant):
                            restriction = item.value
                            self.declared_restrictions.append(str(restriction))
    
    def _check_dangerous_calls(self, node: ast.FunctionDef):
        """Vérifie les appels dangereux dans une fonction"""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in ['eval', 'exec', 'compile']:
                        self.risk_factors.append(
                            f"Utilisation de {child.func.id} dans {node.name}"
                        )

