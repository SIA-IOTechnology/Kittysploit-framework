#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List, Union
from core.module_loader import ModuleLoader
from core.session import Session
from core.output_handler import OutputHandler
from core.session_manager import SessionManager
from core.models.models import Module
from core.db_manager import DatabaseManager
from core.workspace_manager import WorkspaceManager
from core.framework.nops import NopManager
from core.module_sync_manager import ModuleSyncManager
from core.debug_manager import DebugManager
from core.config import Config
from core.charter_manager import CharterManager
from core.encryption_manager import EncryptionManager
from core.framework.shell import ShellManager
from core.plugin_manager import PluginManager
from core.config import Config
from core.utils.validate import validate_module_type
from core.framework.utils.metrics import MetricsCollector
from core.framework.utils.hooks import HookManager, HookPoint
# Runtime Kernel - Couche N+1
from core.framework.runtime import RuntimeKernel, EventBus, EventType
from core.framework.runtime.extension_contract import ExtensionRegistry
from core.framework.runtime.pipeline import Pipeline, PipelineStepType
from core.framework.runtime.hot_reload import HotReloadManager
import os
import importlib.util
import sys
import time


class Framework:
    def __init__(self, clean_sessions: bool = True):
        """Initialise le framework avec ses composants essentiels."""
        self.modules: Dict[str, Any] = {}
        self.current_module: Optional[Any] = None
        self.current_workflow: Optional[Any] = None
        self.version = Config.VERSION
        self.session = Session()
        self.module_loader = ModuleLoader()
        self.output_handler = OutputHandler()
        self.shell_manager = ShellManager()
        self.metrics_collector = MetricsCollector()
        self.hook_manager = HookManager()
        
        # Runtime Kernel - Couche N+1
        self.runtime_kernel = RuntimeKernel()
        self.event_bus = EventBus()
        self.extension_registry = ExtensionRegistry()
        self.hot_reload_manager = HotReloadManager(event_bus=self.event_bus)
        
        # Initialiser les extensions avec le contexte
        extension_context = {
            "hook_manager": self.hook_manager,
            "event_bus": self.event_bus,
            "framework": self
        }
        self.extension_registry.initialize_all(extension_context)
        
        # Initialize proxy configuration from config
        config_instance = Config.get_instance()
        proxy_config = config_instance.get_config_value('proxy')
        if proxy_config:
            # Ensure all required keys exist
            self.proxy_config = Config.DEFAULT_PROXY_CONFIG.copy()
            self.proxy_config.update(proxy_config)
        else:
            # Use default if not found
            self.proxy_config = Config.PROXY_CONFIG.copy()
        
        # Initialize encryption manager first (needed for database)
        self.encryption_manager = EncryptionManager()
        
        # Initialize workspace management from config
        config_instance = Config.get_instance()
        self.workspaces_dir = config_instance.get_config_value_by_path('framework.workspaces_dir') or Config.DEFAULT_WORKSPACES_DIR
        self.current_workspace = config_instance.get_config_value_by_path('framework.default_workspace') or Config.DEFAULT_WORKSPACE
        self.db_manager = DatabaseManager(self.workspaces_dir, self.encryption_manager)
        self.workspace_manager = WorkspaceManager(self.db_manager)
        
        # Now initialize session manager with db_manager
        self.session_manager = SessionManager(clean_startup=clean_sessions, db_manager=self.db_manager, framework=self)
        
        # Initialize browser server reference
        self.browser_server = None
        
        # Initialize module sync manager
        self.module_sync_manager = ModuleSyncManager(self.db_manager, self.current_workspace)
        
        # Initialize module loader with sync manager
        self.module_loader = ModuleLoader(sync_manager=self.module_sync_manager)
        
        # Initialize NOP manager
        self.nops = NopManager()
        
        # Initialize debug manager
        self.debug_manager = DebugManager()
        # Register debug manager with output handler
        from core.output_handler import set_debug_manager
        set_debug_manager(self.debug_manager)
        
        # Initialize charter manager
        self.charter_manager = CharterManager()
        
        # Initialize plugin manager
        self.plugin_manager = PluginManager(self)
        
        # Registry for active listeners (by listener_id)
        self.active_listeners: Dict[str, Any] = {}
        
        # Initialize sound notifications (disabled by default)
        self.sound_enabled = False
        
        # Initialize collaboration
        self.collab_server = None
        self.collab_client = None
        
        # Initialize current module
        self.current_module = None
        
        # Initialize workspaces
        self._init_workspaces()
        
        self.current_collab: Optional[Any] = None
    
    def check_charter_acceptance(self) -> bool:
        """
        Check if the charter has been accepted by the user
        
        Returns:
            True if the charter has been accepted, False otherwise
        """
        return self.charter_manager.is_charter_accepted()
    
    def reset_framework(self, reset_database: bool = False) -> bool:
        """
        Reset the framework to first startup state.
        
        This will:
        - Reset encryption (delete encryption files)
        - Reset charter acceptance
        - Optionally reset database
        
        Args:
            reset_database: If True, delete the database file
            
        Returns:
            True if reset successful, False otherwise
        """
        from core.output_handler import print_warning, print_info, print_success, print_error, print_status
        
        print_warning("WARNING: This will reset the framework to first startup state!")
        print_warning("All encrypted data will become unreadable!")
        if reset_database:
            print_warning("Database will be deleted!")
        
        try:
            # Reset encryption
            if self.encryption_manager.is_initialized():
                if not self.encryption_manager.reset_encryption():
                    print_error("Failed to reset encryption.")
                    return False
                print_success("Encryption reset successfully.")
            
            # Reset charter acceptance
            if self.charter_manager.is_charter_accepted():
                if not self.charter_manager.reset_charter_acceptance():
                    print_error("Failed to reset charter acceptance.")
                    return False
                print_success("Charter acceptance reset successfully.")
            
            # Reset database if requested
            if reset_database:
                db_path = os.path.join("database", "database.db")
                if os.path.exists(db_path):
                    try:
                        os.remove(db_path)
                        print_success("Database deleted successfully.")
                    except Exception as e:
                        print_error(f"Failed to delete database: {e}")
                        return False
            
            print_success("Framework reset successfully!")
            print_status("The framework will behave as on first startup.")
            print_status("You will need to:")
            print_status("    - Accept the charter again")
            print_status("    - Set up encryption again")
            return True
            
        except Exception as e:
            print_error(f"Error resetting framework: {e}")
            return False
    
    def prompt_charter_acceptance(self) -> bool:
        """
        Ask the user to accept the charter
        
        Returns:
            True if the user accepts, False otherwise
        """
        return self.charter_manager.prompt_charter_acceptance()
    
    def initialize_encryption(self, password: str = None) -> bool:
        """
        Initialize encryption for sensitive data
        
        Args:
            password: Master password (if None, will prompt)
            
        Returns:
            True if initialization successful, False otherwise
        """
        return self.encryption_manager.initialize_encryption(password)
    
    def load_encryption(self, password: str = None) -> bool:
        """
        Load encryption with master password
        
        Args:
            password: Master password (if None, will prompt)
            
        Returns:
            True if loading successful, False otherwise
        """
        success = self.encryption_manager.load_encryption(password)
        if success:
            # Update database manager with loaded encryption
            self.db_manager.set_encryption_manager(self.encryption_manager)
        return success
    
    def is_encryption_initialized(self) -> bool:
        """
        Check if encryption is initialized
        
        Returns:
            True if encryption is initialized, False otherwise
        """
        return self.encryption_manager.is_initialized()
    
    def is_encryption_loaded(self) -> bool:
        """
        Check if encryption is loaded and ready to use
        
        Returns:
            True if encryption is loaded, False otherwise
        """
        return self.encryption_manager._is_initialized
    
    def encrypt_sensitive_data(self, data) -> str:
        """
        Encrypt sensitive data
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data
        """
        return self.encryption_manager.encrypt_data(data)
    
    def decrypt_sensitive_data(self, encrypted_data: str):
        """
        Decrypt sensitive data
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Decrypted data
        """
        return self.encryption_manager.decrypt_data(encrypted_data)
    
    def get_current_module(self):

        return self.current_module
    
    def get_available_modules(self) -> Dict[str, Any]:
        """
        Retourne tous les modules disponibles.
        
        Returns:
            Dict[str, Any]: Modules disponibles
        """
        return self.modules
    
    def get_available_exploits(self) -> Dict[str, Any]:
        """
        Retourne tous les exploits disponibles.
        
        Returns:
            Dict[str, Any]: Exploits disponibles
        """
        return self.modules['exploits']
    
    
    def load_core_modules(self) -> None:
        """Charge uniquement les modules essentiels."""
        try:
            # Charger uniquement les modules de base
            core_modules = {
                'remotescan': [],
                'auxiliary': [],
                'exploits': []
            }
            self.modules = core_modules
            
            # Initialiser la base de données des modules
            self._init_modules_db()
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors du chargement des modules de base: {str(e)}")
    
    def _init_modules_db(self) -> None:
        """Initialise la base de données des modules."""
        try:
            session = self.get_db_session()
            if not session:
                return
                
            # Vérifier si la table des modules existe
            if not session.query(Module).first():
                # Charger les modules depuis les fichiers
                self._load_modules_from_files(session)
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors de l'initialisation de la base de données des modules: {str(e)}")
    
    def _load_modules_from_files(self, session) -> None:
        """Charge les modules depuis les fichiers dans la base de données."""
        try:
            # Parcourir les dossiers de modules
            module_dirs = ['modules/exploits', 'modules/auxiliary', 'modules/scanners', 'modules/workflow']
            for module_dir in module_dirs:
                if not os.path.exists(module_dir):
                    continue
                    
                for root, _, files in os.walk(module_dir):
                    for file in files:
                        if file.endswith('.py') and not file.startswith('__'):
                            module_path = os.path.join(root, file)
                            module_info = self.module_loader.get_module_info(module_path)
                            
                            if module_info:
                                # Créer une entrée dans la base de données
                                module = Module(
                                    name=module_info.get('name', ''),
                                    description=module_info.get('description', ''),
                                    type=os.path.basename(os.path.dirname(module_path)),
                                    path=module_path,
                                    author=module_info.get('author', ''),
                                    version=module_info.get('version', ''),
                                    cve=module_info.get('cve', ''),
                                    references=str(module_info.get('references', [])),
                                    options=str(module_info.get('options', {}))
                                )
                                session.add(module)
            
            session.commit()
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors du chargement des modules depuis les fichiers: {str(e)}")
    
    def get_modules_by_type(self, module_type: str) -> List[Module]:
        """
        Récupère tous les modules d'un type spécifique depuis la base de données.
        
        Args:
            module_type: Type de module à récupérer (exploits, auxiliary, etc.)
            
        Returns:
            List[Module]: Liste des modules du type spécifié
        """
        try:
            session = self.get_db_session()
            if not session:
                return []
                
            return session.query(Module).filter_by(type=module_type, is_active=True).all()
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors de la récupération des modules: {str(e)}")
            return []
    
    def get_module_count(self, module_type: str = None) -> int:
        """
        Récupère le nombre de modules, optionnellement filtré par type.
        
        Args:
            module_type: Type de module à compter (optionnel)
            
        Returns:
            int: Nombre de modules
        """
        try:
            session = self.get_db_session()
            if not session:
                return 0
                
            query = session.query(Module).filter_by(is_active=True)
            if module_type:
                query = query.filter_by(type=module_type)
                
            return query.count()
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors du comptage des modules: {str(e)}")
            return 0
    
    def get_module_counts_by_type(self) -> Dict[str, int]:
        """
        Récupère le nombre de modules par type.
        
        Returns:
            Dict[str, int]: Dictionnaire avec le type de module comme clé et le nombre comme valeur
        """
        try:
            # Essayer d'abord avec la base de données
            session = self.get_db_session()
            if session:
                try:
                    # Types de modules supportés
                    module_types = ['exploits', 'auxiliary', 'payloads', 'encoders', 'listeners', 'backdoors', 'workflow', 'browser_exploits', 'browser_auxiliary', 'docker_environment', 'environments', 'post', 'remotescan', 'shortcut']
                    counts = {}
                    
                    for module_type in module_types:
                        count = session.query(Module).filter_by(type=module_type, is_active=True).count()
                        if count > 0:
                            counts[module_type] = count
                    
                    # Si on a des résultats, les retourner
                    if counts:
                        return counts
                except Exception as db_error:
                    # Si erreur de base de données (schéma obsolète), utiliser le fallback
                    # Fallback silencieux - pas besoin de logger
                    pass
            
            # Fallback: compter depuis les fichiers
            counts = self._count_modules_from_files()
            
            # Ajouter le nombre de plugins
            if hasattr(self, 'plugin_manager') and self.plugin_manager:
                plugin_count = len(self.plugin_manager.list_plugins())
                if plugin_count > 0:
                    counts['plugins'] = plugin_count
            
            return counts
            
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors du comptage des modules par type: {str(e)}")
            return {}
    
    def _count_modules_from_files(self) -> Dict[str, int]:
        """
        Compte les modules depuis les fichiers (fallback si la base de données n'est pas disponible).
        
        Returns:
            Dict[str, int]: Dictionnaire avec le type de module comme clé et le nombre comme valeur
        """
        try:
            counts = {}
            modules_path = "modules"
            
            if not os.path.exists(modules_path):
                return counts
            
            # Types de modules supportés
            module_types = ['exploits', 'auxiliary', 'payloads', 'encoders', 'listeners', 'backdoors', 'workflow', 'browser_exploits', 'browser_auxiliary', 'docker_environment', 'environments', 'post', 'remotescan', 'shortcut']
            
            for module_type in module_types:
                # Map module_type to directory name
                if module_type == 'docker_environment':
                    type_path = os.path.join(modules_path, 'docker_environments')
                else:
                    type_path = os.path.join(modules_path, module_type)
                
                if os.path.exists(type_path):
                    count = 0
                    for root, dirs, files in os.walk(type_path):
                        for file in files:
                            if file.endswith(".py") and not file.startswith("__"):
                                count += 1
                    if count > 0:
                        counts[module_type] = count
            
            return counts
            
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors du comptage des modules depuis les fichiers: {str(e)}")
            return {}
    
    def get_exploits_and_auxiliary(self, module_type: str) -> Dict[str, Any]:
        """
        Retourne uniquement les modules de type exploits et auxiliary.
        
        Args:
            module_type: Type de module à récupérer ('exploits' ou 'auxiliary')
            
        Returns:
            Dict[str, Any]: Modules du type spécifié
        """
        if not validate_module_type(module_type):
            self.output_handler.print_warning(f"Type de module non supporté: {module_type}")
            return {}
            
        try:
            modules = self.get_modules_by_type(module_type)
            return {module_type: [module.to_dict() for module in modules]}
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors de la récupération des modules: {str(e)}")
            return {}
    
    def load_module(self, module_path: str, load_only=False) -> Any:
        """
        Charge un module spécifique.
        
        Args:
            module_path: Chemin du module à charger
            
        Returns:
            Any: L'objet module chargé ou None en cas d'échec
        """
        try:
            # Debug: Check for blocked actions first
            if self.debug_manager.is_active:
                # Check if any module_load actions are blocked
                blocked_actions = [action for action in self.debug_manager.actions 
                                 if action.type == "module_load" and action.blocked]
                
                if blocked_actions:
                    # Find the most recent blocked module_load action
                    latest_blocked = max(blocked_actions, key=lambda x: x.timestamp)
                    self.debug_manager.add_action(
                        "module_load_blocked",
                        f"Module load blocked: {module_path}",
                        {"module_path": module_path, "blocked_action_id": latest_blocked.id}
                    )
                    return None
                
                # If not blocked, create the action
                action_id = self.debug_manager.add_action(
                    "module_load",
                    f"Loading module: {module_path}",
                    {"module_path": module_path, "load_only": load_only}
                )
            
            # Publier événement avant chargement
            self.event_bus.publish(
                EventType.MODULE_LOADING,
                {"module_path": module_path, "load_only": load_only},
                source="framework"
            )
            
            # Execute before module load hooks
            if self.hook_manager.has_hook(HookPoint.BEFORE_MODULE_LOAD):
                self.hook_manager.execute(HookPoint.BEFORE_MODULE_LOAD, module_path, load_only, framework=self)
            # Load module
            module = self.module_loader.load_module(module_path, load_only, framework=self)
            # Execute after module load hooks
            if self.hook_manager.has_hook(HookPoint.AFTER_MODULE_LOAD):
                self.hook_manager.execute(HookPoint.AFTER_MODULE_LOAD, module_path, module, framework=self)
            if module:
                self.current_module = module
                
                # Enregistrer pour hot reload
                module_file = os.path.join("modules", module_path.replace("/", os.sep) + ".py")
                if os.path.exists(module_file):
                    self.hot_reload_manager.register_module(module_path, module_file)
                
                # Publier événement après chargement
                self.event_bus.publish(
                    EventType.MODULE_LOADED,
                    {
                        "module_path": module_path,
                        "module_type": getattr(module, 'type', 'unknown'),
                        "module_name": getattr(module, 'name', 'unknown')
                    },
                    source="framework"
                )
                
                # Debug: Capture successful module load
                if self.debug_manager.is_active:
                    self.debug_manager.add_action(
                        "module_loaded",
                        f"Successfully loaded module: {module_path}",
                        {"module_path": module_path, "module_type": getattr(module, 'type', 'unknown')}
                    )
                
                return module
                
            return None
        except Exception as e:
            # Publier événement d'erreur
            self.event_bus.publish(
                EventType.MODULE_FAILED,
                {"module_path": module_path, "error": str(e)},
                source="framework"
            )
            
            # Debug: Capture module load error
            if self.debug_manager.is_active:
                self.debug_manager.add_action(
                    "module_load_error",
                    f"Failed to load module: {module_path}",
                    {"module_path": module_path, "error": str(e)}
                )
            return None
    
    def execute_module(self, use_runtime_kernel: bool = True) -> Any:
        """
        Exécute le module actuellement chargé.
        
        Args:
            use_runtime_kernel: Si True, utilise le Runtime Kernel pour l'exécution avec sandbox
        
        Returns:
            Any: Résultat de l'exécution du module ou False en cas d'erreur
        """
        if not self.current_module:
            self.output_handler.print_warning("Tentative d'exécution sans module chargé")
            return False
        
        # Utiliser le Runtime Kernel si demandé
        if use_runtime_kernel:
            module_path = getattr(self.current_module, '__module__', 'unknown')
            module_id = f"{module_path}_{int(time.time() * 1000)}"
            
            # Publier événement avant exécution
            self.event_bus.publish(
                EventType.MODULE_EXECUTING,
                {"module_path": module_path, "module_id": module_id},
                source="framework"
            )
            
            # Exécuter via le Runtime Kernel
            context = self.runtime_kernel.execute_module(
                module_path=module_path,
                module_instance=self.current_module,
                module_id=module_id,
                sandbox_config=None,  # Peut être configuré via les policies
                resource_limits=None,  # Peut être configuré
                timeout=None
            )
            
            # Attendre la fin de l'exécution
            if context.execution_thread:
                context.execution_thread.join(timeout=300)  # Timeout de 5 minutes
            
            # Publier événement après exécution
            if context.status == "completed":
                self.event_bus.publish(
                    EventType.MODULE_EXECUTED,
                    {"module_path": module_path, "module_id": module_id, "result": context.result},
                    source="framework"
                )
                return context.result
            else:
                self.event_bus.publish(
                    EventType.MODULE_FAILED,
                    {"module_path": module_path, "module_id": module_id, "error": context.error},
                    source="framework"
                )
                return False
        
        # Debug: Check for blocked actions first
        if self.debug_manager.is_active:
            # Check if any module_execute_start actions are blocked
            blocked_actions = [action for action in self.debug_manager.actions 
                             if action.type == "module_execute_start" and action.blocked]
            
            if blocked_actions:
                # Find the most recent blocked module_execute_start action
                latest_blocked = max(blocked_actions, key=lambda x: x.timestamp)
                self.debug_manager.add_action(
                    "module_execute_blocked",
                    f"Module execution blocked: {getattr(self.current_module, 'name', 'unknown')}",
                    {"module": getattr(self.current_module, 'name', 'unknown'), "blocked_action_id": latest_blocked.id}
                )
                return False
            
            # If not blocked, create the action
            action_id = self.debug_manager.add_action(
                "module_execute_start",
                f"Starting execution of module: {getattr(self.current_module, 'name', 'unknown')}",
                {"module_path": getattr(self.current_module, '__module__', 'unknown')}
            )
        
        # Vérifier que toutes les options requises sont définies
        if not self.current_module.check_options():
            missing = self.current_module.get_missing_options()
            if missing:
                self.output_handler.print_error(f"Exécution impossible: options requises manquantes: {', '.join(missing)}")
            else:
                self.output_handler.print_error("Exécution impossible: toutes les options requises ne sont pas définies")
            
            # Debug: Capture options check failure
            if self.debug_manager.is_active:
                self.debug_manager.add_action(
                    "module_execute_failed",
                    "Module execution failed: missing required options",
                    {"module": getattr(self.current_module, 'name', 'unknown')}
                )
            return False
        
        try:
            # Reset auto-return flags for BrowserAuxiliary modules before execution
            try:
                from core.framework.browserauxiliary import BrowserAuxiliary
                if isinstance(self.current_module, BrowserAuxiliary):
                    self.current_module._reset_auto_return_flags()
            except ImportError:
                pass  # BrowserAuxiliary not available
            
            # Record module execution start time
            start_time = time.time()
            
            # Définir le contexte de métadonnées pour les métriques
            module_name = getattr(self.current_module, 'name', 'unknown')
            module_type = getattr(self.current_module, 'module_type', 'unknown')
            workspace = self.get_current_workspace_name()
            
            self.metrics_collector.set_metadata_context(
                module=module_name,
                module_type=module_type,
                workspace=workspace
            )
            
            result = self.current_module.run()
            duration = time.time() - start_time
            
            self.metrics_collector.record_timing("module.execution.duration", duration, {
                "module": module_name,
                "module_type": module_type,
                "workspace": workspace
            })
            self.metrics_collector.increment("module.execution.success", metadata={
                "module": module_name,
                "module_type": module_type,
                "workspace": workspace
            })
            
            # Effacer le contexte après l'exécution
            self.metrics_collector.clear_metadata_context()
            # Auto-return handling for BrowserAuxiliary modules
            # If run() returns None but execute_js was called, use the stored result
            try:
                from core.framework.browserauxiliary import BrowserAuxiliary
                if result is None and isinstance(self.current_module, BrowserAuxiliary):
                    # Check if execute_js was actually called (not just initialized)
                    if hasattr(self.current_module, '_execute_js_called') and self.current_module._execute_js_called:
                        # Use the stored result from execute_js
                        result = self.current_module._last_js_result
                        # Clear the flags for next execution
                        self.current_module._last_js_result = None
                        self.current_module._execute_js_called = False
            except ImportError:
                pass  # BrowserAuxiliary not available, skip auto-return
            except Exception as e:
                # Don't let auto-return handling break module execution
                if self.debug_manager.is_active:
                    print_debug(f"Error in auto-return handling: {e}")
                pass
            
            # Debug: Capture successful execution
            if self.debug_manager.is_active:
                self.debug_manager.add_action(
                    "module_execute_success",
                    f"Module executed successfully: {getattr(self.current_module, 'name', 'unknown')}",
                    {"module": getattr(self.current_module, 'name', 'unknown'), "result": str(result)}
                )
            
            return result
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors de l'exécution du module: {str(e)}")
            
            # Enregistrer l'échec dans les métriques
            module_name = getattr(self.current_module, 'name', 'unknown') if self.current_module else 'unknown'
            module_type = getattr(self.current_module, 'module_type', 'unknown') if self.current_module else 'unknown'
            workspace = self.get_current_workspace_name()
            
            self.metrics_collector.increment("module.execution.failure", metadata={
                "module": module_name,
                "module_type": module_type,
                "workspace": workspace,
                "error": str(e)
            })
            
            # Effacer le contexte
            self.metrics_collector.clear_metadata_context()
            
            # Debug: Capture execution error
            if self.debug_manager.is_active:
                self.debug_manager.add_action(
                    "module_execute_error",
                    f"Module execution error: {module_name}",
                    {"module": module_name, "error": str(e)}
                )
            return False
    
    def get_module_options(self) -> Dict[str, Any]:
        """
        Retourne les options du module actuel.
        
        Returns:
            Dict[str, Any]: Options du module ou dictionnaire vide si aucun module n'est chargé
        """
        if not self.current_module:
            return {}
        return self.current_module.get_options()
    
    def set_module_option(self, option_name: str, value: Any) -> bool:
        """
        Définit une option pour le module actuel.
        
        Args:
            option_name: Nom de l'option
            value: Valeur à attribuer
            
        Returns:
            bool: True si l'option a été définie avec succès, False sinon
        """
        if not self.current_module:
            self.output_handler.print_warning(f"Tentative de définir l'option '{option_name}' sans module chargé")
            return False
            
        success = self.current_module.set_option(option_name, value)
        if success:
            self.output_handler.print_success(f"Option '{option_name}' définie avec succès")
        else:
            self.output_handler.print_error(f"Échec de définition de l'option '{option_name}'")
        return success
    
    def get_modules(self, path: Optional[str] = None) -> Union[Dict[str, Any], List[Any]]:
        """
        Récupère les modules disponibles.
        
        Args:
            path: Chemin optionnel pour récupérer les sous-modules
            
        Returns:
            Union[Dict[str, Any], List[Any]]: Modules correspondants au chemin demandé
        """
        if path:
            # Si un chemin est spécifié, récupérer les sous-modules
            parts = path.split('/')
            current = self.modules
            
            for part in parts:
                if part in current:
                    current = current[part]
                else:
                    return {'error': f"Chemin de module non trouvé: {path}"}
            
            return current
        else:
            # Sinon, renvoyer tous les modules
            return self.modules

    def get_module_info(self, module_path):
        """Obtient les informations sur un module"""
        return self.module_loader.get_module_info(module_path)

    def load_all_plugins(self) -> None:
        """Charge tous les plugins disponibles (deprecated - plugins are now loaded on demand)"""
        # Plugins are now loaded on demand when executed
        # This method is kept for backward compatibility but does nothing
        pass

    def _init_workspaces(self) -> None:
        """Initialize workspace management system"""
        # Initialize database for default workspace (needed for workspace management)
        self.db_manager.init_workspace_db("default")
        
        # Initialize default workspace in database
        self.workspace_manager.init_default_workspace()
        
        # Initialize database for the actual workspace from config
        # This ensures the database is ready for the workspace specified in config
        if self.current_workspace:
            self.db_manager.init_workspace_db(self.current_workspace)
            
            # Try to load the workspace from database and set it as current in WorkspaceManager
            try:
                session = self.db_manager.get_session("default")
                if session:
                    from core.models.models import Workspace
                    workspace = session.query(Workspace).filter(Workspace.name == self.current_workspace).first()
                    if workspace:
                        try:
                            session.expunge(workspace)
                        except Exception:
                            pass
                        self.workspace_manager.current_workspace = workspace
                    else:
                        # If workspace doesn't exist, create it
                        if self.workspace_manager.create_workspace(self.current_workspace, f"Workspace {self.current_workspace}"):
                            # Reload to get the created workspace
                            workspace = session.query(Workspace).filter(Workspace.name == self.current_workspace).first()
                            if workspace:
                                try:
                                    session.expunge(workspace)
                                except Exception:
                                    pass
                                self.workspace_manager.current_workspace = workspace
            except Exception as e:
                # If there's an error, fall back to default workspace
                self.output_handler.print_warning(f"Could not load workspace '{self.current_workspace}' from config, using default: {e}")
                self.current_workspace = "default"
                try:
                    session = self.db_manager.get_session("default")
                    if session:
                        from core.models.models import Workspace
                        workspace = session.query(Workspace).filter(Workspace.name == "default").first()
                        if workspace:
                            try:
                                session.expunge(workspace)
                            except Exception:
                                pass
                            self.workspace_manager.current_workspace = workspace
                except Exception:
                    # If we can't even get default workspace, just continue
                    pass
                finally:
                    # Update module_sync_manager with the fallback workspace
                    if hasattr(self, 'module_sync_manager'):
                        self.module_sync_manager.workspace = self.current_workspace
    
    def get_current_workspace_name(self) -> str:
        """Get the current workspace name"""
        current_workspace = self.workspace_manager.get_current_workspace()
        return current_workspace.name if current_workspace else "default"
    
    def get_workspaces(self) -> List[str]:
        """Get list of available workspaces
        
        Returns:
            List[str]: List of workspace names
        """
        try:
            workspaces = self.workspace_manager.list_workspaces()
            return [w.name for w in workspaces]
        except Exception as e:
            self.output_handler.print_error(f"Error listing workspaces: {str(e)}")
            return []
    
    def get_current_workspace(self) -> str:
        """Get the name of the current workspace
        
        Returns:
            str: Name of the current workspace
        """
        return self.get_current_workspace_name()
    
    def create_workspace(self, name: str, description: str = None) -> bool:
        """Create a new workspace
        
        Args:
            name: Name of the workspace to create
            description: Description of the workspace
            
        Returns:
            bool: True if workspace was created successfully, False otherwise
        """
        return self.workspace_manager.create_workspace(name, description)
    
    def delete_workspace(self, name: str, force: bool = False) -> bool:
        """Delete a workspace
        
        Args:
            name: Name of the workspace to delete
            force: Force deletion without confirmation
            
        Returns:
            bool: True if workspace was deleted successfully, False otherwise
        """
        return self.workspace_manager.delete_workspace(name, force)
    
    def set_workspace(self, name: str) -> bool:
        """Switch to a different workspace
        
        Args:
            name: Name of the workspace to switch to
            
        Returns:
            bool: True if workspace was switched successfully, False otherwise
        """
        # Switch workspace in WorkspaceManager first
        success = self.workspace_manager.switch_workspace(name)
        if success:
            # Update self.current_workspace to keep it in sync
            self.current_workspace = name
            
            # Initialize database for the new workspace if not already initialized
            self.db_manager.init_workspace_db(name)
            
            # Update module_sync_manager with the new workspace
            if hasattr(self, 'module_sync_manager'):
                self.module_sync_manager.workspace = name
        
        return success
    
    def get_db_session(self):
        """Get the database session for the current workspace
        
        Returns:
            Session: SQLAlchemy session for the current workspace
        """
        # Ensure we have a valid workspace name
        workspace_name = self.current_workspace
        if not workspace_name:
            # Fall back to getting it from WorkspaceManager
            current_workspace = self.workspace_manager.get_current_workspace()
            workspace_name = current_workspace.name if current_workspace else "default"
            self.current_workspace = workspace_name
        
        # Initialize database for workspace if not already initialized
        if workspace_name not in self.db_manager.sessions:
            self.db_manager.init_workspace_db(workspace_name)
        
        return self.db_manager.get_session(workspace_name)

    def configure_proxy(self, enabled: bool = True, host: str = '127.0.0.1', port: int = 8080,
            scheme: str = 'http', username: str = None, password: str = None):
        """Configure HTTP/HTTPS/SOCKS proxies for the framework."""
        self.proxy_config['enabled'] = enabled
        if enabled:
            scheme = (scheme or 'http').lower()
            proxy_url = f"{scheme}://{host}:{port}"

            self.proxy_config['protocol'] = scheme
            self.proxy_config['username'] = username
            self.proxy_config['password'] = password

            if scheme.startswith('socks'):
                self.proxy_config['socks_proxy'] = proxy_url
                self.proxy_config['http_proxy'] = proxy_url
                self.proxy_config['https_proxy'] = proxy_url
                os.environ['HTTP_PROXY'] = proxy_url
                os.environ['HTTPS_PROXY'] = proxy_url
                os.environ['ALL_PROXY'] = proxy_url
            else:
                self.proxy_config['socks_proxy'] = None
                self.proxy_config['http_proxy'] = proxy_url
                self.proxy_config['https_proxy'] = proxy_url
                os.environ['HTTP_PROXY'] = proxy_url
                os.environ['HTTPS_PROXY'] = proxy_url
                os.environ.pop('ALL_PROXY', None)

            os.environ['NO_PROXY'] = self.proxy_config['no_proxy']
            # Proxy configured - no need to log
        else:
            for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'):
                os.environ.pop(key, None)

            self.proxy_config['http_proxy'] = None
            self.proxy_config['https_proxy'] = None
            self.proxy_config['socks_proxy'] = None
            self.proxy_config['protocol'] = 'http'
            self.proxy_config['username'] = None
            self.proxy_config['password'] = None

            # Proxy disabled - no need to log

    def get_proxy_config(self) -> Dict[str, Any]:
        """Retourne la configuration actuelle du proxy"""
        return self.proxy_config.copy()
    
    def is_proxy_enabled(self) -> bool:
        """Vérifie si le proxy est activé"""
        return self.proxy_config['enabled']
    
    def get_proxy_url(self) -> Optional[str]:
        """Retourne l'URL du proxy si activé"""
        if self.proxy_config['enabled']:
            return self.proxy_config['http_proxy']
        return None
    
    # Module Synchronization Methods
    
    def start_module_sync(self, interval: int = 300):
        """Start background module synchronization"""
        self.module_sync_manager.start_background_sync(interval)
    
    def stop_module_sync(self):
        """Stop background module synchronization"""
        self.module_sync_manager.stop_background_sync()
    
    def sync_modules_now(self) -> Dict[str, int]:
        """Perform immediate module synchronization"""
        return self.module_sync_manager.sync_modules(force=True)
    
    def get_module_sync_status(self) -> Dict:
        """Get module synchronization status"""
        return self.module_sync_manager.get_sync_status()
    
    def search_modules_db(self, query: str = "", module_type: str = "", 
                         author: str = "", cve: str = "", limit: int = 100) -> List[Dict]:
        """Search modules in database (faster than filesystem search)"""
        return self.module_loader.search_modules_db(query, module_type, author, cve, limit)
    
    def get_module_stats_db(self) -> Dict[str, int]:
        """Get module statistics from database"""
        return self.module_loader.get_module_stats_db()
    
    # Browser Server Methods
    
    def set_browser_server(self, browser_server):
        """Set the browser server instance for the framework"""
        self.browser_server = browser_server
    
    def get_browser_server(self):
        """Get the current browser server instance"""
        return self.browser_server
    
    def has_browser_server(self) -> bool:
        """Check if browser server is available"""
        return self.browser_server is not None
