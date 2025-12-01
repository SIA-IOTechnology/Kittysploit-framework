from typing import Dict, List, Any, Optional
import ast
import inspect

# Import du PolicyEngine pour la validation avancée
try:
    from core.framework.utils.policy_engine import PolicyEngine, PolicyLevel
    POLICY_ENGINE_AVAILABLE = True
except ImportError:
    POLICY_ENGINE_AVAILABLE = False


class ModuleValidator:
    """Validate modules before loading - Wrapper autour du PolicyEngine"""
    
    def __init__(
        self,
        use_policy_engine: bool = True,
        policy_level: str = "standard",
        encryption_manager=None
    ):
        """
        Initialise le validateur de modules
        
        Args:
            use_policy_engine: Utiliser le PolicyEngine avancé si disponible
            policy_level: Niveau de politique (permissive, standard, strict, paranoid)
            encryption_manager: Instance d'EncryptionManager pour les signatures
        """
        self.use_policy_engine = use_policy_engine and POLICY_ENGINE_AVAILABLE
        self.policy_engine = None
        
        if self.use_policy_engine:
            try:
                policy_level_enum = PolicyLevel[policy_level.upper()] if hasattr(PolicyLevel, policy_level.upper()) else PolicyLevel.STANDARD
                self.policy_engine = PolicyEngine(
                    encryption_manager=encryption_manager,
                    policy_level=policy_level_enum
                )
            except Exception as e:
                # Fallback vers validation basique si PolicyEngine échoue
                self.use_policy_engine = False
    
    def validate(self, module_path: str, module_code: str) -> Dict[str, Any]:
        """
        Validate a module
        
        Args:
            module_path: Chemin du module
            module_code: Code source du module
            
        Returns:
            Résultats de validation
        """
        # Utiliser PolicyEngine si disponible
        if self.use_policy_engine and self.policy_engine:
            return self.policy_engine.validate_module(
                module_path=module_path,
                module_code=module_code,
                require_approval=False,  # Pas d'approbation requise pour compatibilité
                enable_sandbox=None,  # Selon policy_level
                enable_differential=False
            )
        
        # Fallback vers validation basique
        return self._basic_validate(module_path, module_code)
    
    def _basic_validate(self, module_path: str, module_code: str) -> Dict[str, Any]:
        """Validation basique (compatibilité)"""
        errors = []
        warnings = []
        
        # Parse AST
        try:
            tree = ast.parse(module_code)
        except SyntaxError as e:
            return {"valid": False, "errors": [f"Syntax error: {e}"]}
        
        # Check for Module class
        has_module_class = any(
            isinstance(node, ast.ClassDef) and node.name == "Module"
            for node in ast.walk(tree)
        )
        if not has_module_class:
            errors.append("Module must define a 'Module' class")
        
        # Check for __info__ dictionary
        has_info = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__info__":
                        has_info = True
                        # Validate __info__ structure
                        if isinstance(node.value, ast.Dict):
                            required_keys = ["name", "description"]
                            keys = []
                            for k in node.value.keys:
                                if isinstance(k, ast.Str):
                                    keys.append(k.s)
                                elif isinstance(k, ast.Constant):
                                    keys.append(k.value)
                            for req_key in required_keys:
                                if req_key not in keys:
                                    errors.append(f"__info__ must contain '{req_key}'")
        
        if not has_info:
            warnings.append("Module should define __info__ dictionary")
        
        # Check for run() method
        has_run = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "run":
                has_run = True
                break
        
        if not has_run:
            errors.append("Module must define a 'run()' method")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }