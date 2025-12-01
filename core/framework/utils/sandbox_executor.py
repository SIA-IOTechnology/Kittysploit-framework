#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sandbox Executor - Exécution contrôlée de modules dans un environnement isolé
"""

import sys
import os
import time
import threading
import traceback
from typing import Dict, List, Any, Optional, Set
from contextlib import contextmanager
import importlib.util


class SandboxExecutor:
    """Exécuteur de sandbox pour tester les modules de manière sécurisée"""
    
    def __init__(self):
        """Initialise l'exécuteur de sandbox"""
        self.blocked_modules: Set[str] = {
            'os', 'sys', 'subprocess', 'socket', 'shutil', 'ctypes',
            'pickle', 'marshal', 'eval', 'exec', '__builtin__', '__builtins__'
        }
        self.blocked_functions: Set[str] = {
            'eval', 'exec', 'compile', '__import__', 'open', 'file',
            'input', 'raw_input', 'execfile', 'reload'
        }
        self.suspicious_actions: List[Dict[str, Any]] = []
    
    def execute_safely(
        self,
        module_code: str,
        module_path: str,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Exécute un module de manière sécurisée dans un sandbox
        
        Args:
            module_code: Code source du module
            module_path: Chemin du module
            timeout: Timeout en secondes
            
        Returns:
            Résultats de l'exécution sandbox
        """
        result = {
            "safe": True,
            "executed": False,
            "errors": [],
            "warnings": [],
            "suspicious_actions": [],
            "execution_time": 0.0,
            "memory_usage": 0
        }
        
        # Créer un environnement isolé
        sandbox_env = self._create_sandbox_environment()
        
        # Intercepter les imports dangereux
        import builtins
        original_import = builtins.__import__
        
        def safe_import(name, *args, **kwargs):
            if name in self.blocked_modules:
                raise ImportError(f"Module '{name}' est bloqué dans le sandbox")
            return original_import(name, *args, **kwargs)
        
        try:
            # Remplacer __import__
            builtins.__import__ = safe_import
            
            # Exécuter dans un thread avec timeout
            execution_result = {"completed": False, "error": None}
            
            def execute():
                try:
                    # Compiler le code
                    code_obj = compile(module_code, module_path, 'exec')
                    
                    # Exécuter dans l'environnement sandbox
                    exec(code_obj, sandbox_env)
                    
                    execution_result["completed"] = True
                except Exception as e:
                    execution_result["error"] = str(e)
                    execution_result["traceback"] = traceback.format_exc()
            
            # Lancer l'exécution avec timeout
            thread = threading.Thread(target=execute)
            thread.daemon = True
            thread.start()
            thread.join(timeout=timeout)
            
            if thread.is_alive():
                result["warnings"].append("Exécution timeout - module peut être bloquant")
                result["safe"] = False
            elif execution_result["error"]:
                result["errors"].append(execution_result["error"])
                result["safe"] = False
            else:
                result["executed"] = True
            
            # Analyser les actions suspectes
            if hasattr(sandbox_env, '_suspicious_actions'):
                result["suspicious_actions"] = sandbox_env._suspicious_actions
            
        except Exception as e:
            result["errors"].append(f"Erreur lors de l'exécution sandbox: {e}")
            result["safe"] = False
        finally:
            # Restaurer __import__
            import builtins
            builtins.__import__ = original_import
        
        return result
    
    def _create_sandbox_environment(self) -> Dict[str, Any]:
        """
        Crée un environnement sandbox isolé
        
        Returns:
            Environnement sandbox
        """
        env = {
            '__builtins__': {
                'print': print,
                'len': len,
                'str': str,
                'int': int,
                'float': float,
                'bool': bool,
                'list': list,
                'dict': dict,
                'tuple': tuple,
                'set': set,
                'range': range,
                'enumerate': enumerate,
                'zip': zip,
                'isinstance': isinstance,
                'type': type,
                'hasattr': hasattr,
                'getattr': getattr,
                'setattr': setattr,
                'Exception': Exception,
                'ValueError': ValueError,
                'TypeError': TypeError,
                'KeyError': KeyError,
                'AttributeError': AttributeError,
            },
            '_suspicious_actions': []
        }
        
        # Ajouter des wrappers pour détecter les actions suspectes
        def safe_open(*args, **kwargs):
            env['_suspicious_actions'].append({
                'action': 'file_open',
                'args': str(args),
                'risk': 'medium'
            })
            raise PermissionError("File operations are blocked in sandbox")
        
        def safe_exec(*args, **kwargs):
            env['_suspicious_actions'].append({
                'action': 'code_execution',
                'args': str(args),
                'risk': 'high'
            })
            raise PermissionError("Code execution is blocked in sandbox")
        
        # Bloquer les fonctions dangereuses
        for func_name in self.blocked_functions:
            env['__builtins__'][func_name] = lambda *args, **kwargs: (
                env['_suspicious_actions'].append({
                    'action': f'blocked_{func_name}',
                    'risk': 'critical'
                }) or exec('raise PermissionError(f"{func_name} is blocked")')
            )
        
        return env

