#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
import importlib
import importlib.util
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import traceback

# Optionnel: psutil pour le monitoring avancé
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    # Créer une classe mock pour psutil.Process
    class MockProcess:
        def cpu_percent(self, interval=0.1):
            return 0.0
        def memory_info(self):
            class MockMemoryInfo:
                rss = 0
            return MockMemoryInfo()
    psutil = type('psutil', (), {'Process': lambda: MockProcess()})()

from core.framework.base_module import BaseModule
from core.framework.utils.sandbox_executor import SandboxExecutor


class ResourceType(Enum):
    """Types de ressources supervisées"""
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    DISK = "disk"
    THREAD = "thread"


@dataclass
class ResourceUsage:
    """Utilisation des ressources par un module"""
    module_id: str
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    disk_read_mb: float = 0.0
    disk_write_mb: float = 0.0
    thread_count: int = 0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)


@dataclass
class ModuleExecutionContext:
    """Contexte d'exécution d'un module"""
    module_id: str
    module_path: str
    module_instance: BaseModule
    sandbox_enabled: bool = True
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    execution_thread: Optional[threading.Thread] = None
    start_time: float = field(default_factory=time.time)
    status: str = "pending"  # pending, running, completed, failed, killed
    result: Any = None
    error: Optional[str] = None


class ResourceSupervisor:
    """Superviseur de ressources pour les modules"""
    
    def __init__(self):
        self.monitored_modules: Dict[str, ResourceUsage] = {}
        self.process = psutil.Process()
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
    
    def start_monitoring(self, interval: float = 1.0):
        """Démarre le monitoring des ressources"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        
        def monitor_loop():
            while self.monitoring_active:
                try:
                    self._update_resources()
                    time.sleep(interval)
                except Exception as e:
                    print(f"Error in resource monitoring: {e}")
        
        self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Arrête le monitoring des ressources"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=2.0)
    
    def register_module(self, module_id: str) -> ResourceUsage:
        """Enregistre un module pour le monitoring"""
        with self.lock:
            if module_id not in self.monitored_modules:
                self.monitored_modules[module_id] = ResourceUsage(module_id=module_id)
            return self.monitored_modules[module_id]
    
    def unregister_module(self, module_id: str):
        """Désenregistre un module du monitoring"""
        with self.lock:
            self.monitored_modules.pop(module_id, None)
    
    def get_resource_usage(self, module_id: str) -> Optional[ResourceUsage]:
        """Récupère l'utilisation des ressources d'un module"""
        with self.lock:
            return self.monitored_modules.get(module_id)
    
    def _update_resources(self):
        """Met à jour les statistiques de ressources"""
        with self.lock:
            # Pour l'instant, on surveille le processus global
            # Dans une implémentation avancée, on pourrait surveiller chaque thread/module
            try:
                cpu_percent = self.process.cpu_percent(interval=0.1)
                memory_info = self.process.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                
                # Mettre à jour tous les modules avec les stats globales
                for usage in self.monitored_modules.values():
                    usage.cpu_percent = cpu_percent
                    usage.memory_mb = memory_mb
                    usage.last_update = time.time()
            except Exception:
                pass
    
    def check_limits(self, module_id: str, limits: Dict[str, Any]) -> Dict[str, bool]:
        """Vérifie si les limites de ressources sont respectées"""
        usage = self.get_resource_usage(module_id)
        if not usage:
            return {}
        
        violations = {}
        
        if "max_cpu_percent" in limits:
            violations["cpu"] = usage.cpu_percent > limits["max_cpu_percent"]
        
        if "max_memory_mb" in limits:
            violations["memory"] = usage.memory_mb > limits["max_memory_mb"]
        
        if "max_execution_time" in limits:
            elapsed = time.time() - usage.start_time
            violations["time"] = elapsed > limits["max_execution_time"]
        
        return violations


class ModuleSandbox:
    """Sandbox isolé pour un module"""
    
    def __init__(self, module_id: str, sandbox_executor: Optional[SandboxExecutor] = None):
        self.module_id = module_id
        self.executor = sandbox_executor or SandboxExecutor()
        self.isolated_env: Dict[str, Any] = {}
        self.allowed_imports: Set[str] = set()
        self.blocked_imports: Set[str] = set()
        self.allowed_functions: Set[str] = set()
        self.blocked_functions: Set[str] = set()
    
    def configure(self, config: Dict[str, Any]):
        """Configure le sandbox"""
        self.allowed_imports = set(config.get("allowed_imports", []))
        self.blocked_imports = set(config.get("blocked_imports", []))
        self.allowed_functions = set(config.get("allowed_functions", []))
        self.blocked_functions = set(config.get("blocked_functions", []))
    
    def is_import_allowed(self, module_name: str) -> bool:
        """Vérifie si un import est autorisé"""
        if module_name in self.blocked_imports:
            return False
        if self.allowed_imports and module_name not in self.allowed_imports:
            return False
        return True
    
    def is_function_allowed(self, function_name: str) -> bool:
        """Vérifie si une fonction est autorisée"""
        if function_name in self.blocked_functions:
            return False
        if self.allowed_functions and function_name not in self.allowed_functions:
            return False
        return True


class RuntimeKernel:
    """
    Runtime Kernel - Couche fondamentale du framework
    
    Fournit:
    - Moteur d'exécution de modules avec sandbox
    - Supervision des ressources
    - Gestion du cycle de vie des modules
    - Support pour hot reload
    """
    
    def __init__(self):
        self.active_modules: Dict[str, ModuleExecutionContext] = {}
        self.module_sandboxes: Dict[str, ModuleSandbox] = {}
        self.resource_supervisor = ResourceSupervisor()
        self.resource_supervisor.start_monitoring()
        self.lock = threading.Lock()
        
        # Cache des modules chargés pour hot reload
        self.module_cache: Dict[str, Any] = {}
        self.module_file_times: Dict[str, float] = {}
    
    def execute_module(
        self,
        module_path: str,
        module_instance: BaseModule,
        module_id: Optional[str] = None,
        sandbox_config: Optional[Dict[str, Any]] = None,
        resource_limits: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None
    ) -> ModuleExecutionContext:
        """
        Exécute un module dans un contexte isolé avec supervision
        
        Args:
            module_path: Chemin du module
            module_instance: Instance du module à exécuter
            module_id: ID unique pour ce module (généré si None)
            sandbox_config: Configuration du sandbox
            resource_limits: Limites de ressources
            timeout: Timeout en secondes
            
        Returns:
            ModuleExecutionContext: Contexte d'exécution
        """
        if module_id is None:
            module_id = f"{module_path}_{int(time.time() * 1000)}"
        
        # Créer le contexte d'exécution
        context = ModuleExecutionContext(
            module_id=module_id,
            module_path=module_path,
            module_instance=module_instance,
            sandbox_enabled=sandbox_config is not None,
            resource_limits=resource_limits or {}
        )
        
        # Créer le sandbox si nécessaire
        if sandbox_config:
            sandbox = ModuleSandbox(module_id)
            sandbox.configure(sandbox_config)
            self.module_sandboxes[module_id] = sandbox
        
        # Enregistrer pour le monitoring
        self.resource_supervisor.register_module(module_id)
        
        # Stocker le contexte
        with self.lock:
            self.active_modules[module_id] = context
        
        # Exécuter dans un thread séparé
        def execute():
            context.status = "running"
            try:
                # Vérifier les limites de ressources avant l'exécution
                if resource_limits:
                    violations = self.resource_supervisor.check_limits(module_id, resource_limits)
                    if any(violations.values()):
                        context.status = "failed"
                        context.error = f"Resource limits violated: {violations}"
                        return
                
                # Vérifier la blacklist du Guardian avant l'exécution
                framework = getattr(module_instance, 'framework', None)
                if framework and hasattr(framework, 'guardian_manager') and framework.guardian_manager and framework.guardian_manager.enabled:
                    target_ip = framework._extract_target_ip_from_module()
                    if target_ip:
                        # Vérifier si l'IP est dans la blacklist
                        if target_ip in framework.guardian_manager.blacklist:
                            blacklist_entry = framework.guardian_manager.blacklist[target_ip]
                            reason = blacklist_entry.get('reason', 'Unknown reason')
                            timestamp = blacklist_entry.get('timestamp', 'Unknown')
                            
                            context.status = "failed"
                            context.error = f"[GUARDIAN] Module execution BLOCKED: Target IP {target_ip} is blacklisted. Reason: {reason} (added: {timestamp})"
                            
                            # Créer une alerte Guardian via _create_alert pour mettre à jour les statistiques
                            alert = framework.guardian_manager._create_alert(
                                target=target_ip,
                                severity="CRITICAL",
                                issue=f"Module execution blocked: IP {target_ip} is blacklisted",
                                confidence=100.0,
                                recommendations=[
                                    "Remove IP from blacklist if this is intentional",
                                    "Verify target before removing from blacklist"
                                ],
                                evidence=[f"IP {target_ip} found in blacklist"]
                            )
                            # Marquer l'action comme prise
                            alert.auto_action_taken = True
                            alert.action_description = "Module execution blocked"
                            
                            # Afficher l'erreur via output_handler si disponible
                            if hasattr(framework, 'output_handler') and framework.output_handler:
                                framework.output_handler.print_error(context.error)
                            
                            return
                
                # Exécuter le module
                result = module_instance.run()
                context.result = result
                context.status = "completed"
                
            except Exception as e:
                context.status = "failed"
                context.error = str(e)
                context.result = None
            finally:
                # Nettoyer
                self.resource_supervisor.unregister_module(module_id)
                with self.lock:
                    if module_id in self.active_modules:
                        del self.active_modules[module_id]
                if module_id in self.module_sandboxes:
                    del self.module_sandboxes[module_id]
        
        execution_thread = threading.Thread(target=execute, daemon=True)
        context.execution_thread = execution_thread
        execution_thread.start()
        
        # Gérer le timeout si spécifié
        if timeout:
            def timeout_handler():
                time.sleep(timeout)
                if context.status == "running":
                    context.status = "killed"
                    context.error = "Execution timeout"
                    # Note: On ne peut pas vraiment tuer un thread Python, mais on marque le statut
        
            timeout_thread = threading.Thread(target=timeout_handler, daemon=True)
            timeout_thread.start()
        
        return context
    
    def get_module_status(self, module_id: str) -> Optional[ModuleExecutionContext]:
        """Récupère le statut d'un module"""
        with self.lock:
            return self.active_modules.get(module_id)
    
    def kill_module(self, module_id: str) -> bool:
        """Arrête l'exécution d'un module"""
        with self.lock:
            context = self.active_modules.get(module_id)
            if not context:
                return False
            
            context.status = "killed"
            context.error = "Module killed by user"
            self.resource_supervisor.unregister_module(module_id)
            
            if module_id in self.module_sandboxes:
                del self.module_sandboxes[module_id]
            
            return True
    
    def get_resource_usage(self, module_id: str) -> Optional[ResourceUsage]:
        """Récupère l'utilisation des ressources d'un module"""
        return self.resource_supervisor.get_resource_usage(module_id)
    
    def reload_module(self, module_path: str) -> bool:
        """
        Recharge un module (hot reload)
        
        Args:
            module_path: Chemin du module à recharger
            
        Returns:
            True si le rechargement a réussi
        """
        try:
            # Vérifier si le fichier a changé
            if module_path in self.module_file_times:
                current_mtime = os.path.getmtime(module_path)
                if current_mtime <= self.module_file_times[module_path]:
                    return True  # Pas de changement
            
            # Recharger le module
            if module_path in self.module_cache:
                module_spec = self.module_cache[module_path]
                if module_spec and hasattr(module_spec, '__name__'):
                    importlib.reload(importlib.import_module(module_spec.__name__))
            
            # Mettre à jour le timestamp
            self.module_file_times[module_path] = os.path.getmtime(module_path)
            return True
            
        except Exception as e:
            print(f"Error reloading module {module_path}: {e}")
            return False
    
    def cleanup(self):
        """Nettoie les ressources du kernel"""
        self.resource_supervisor.stop_monitoring()
        with self.lock:
            # Tuer tous les modules actifs
            for module_id in list(self.active_modules.keys()):
                self.kill_module(module_id)
            self.active_modules.clear()
            self.module_sandboxes.clear()

