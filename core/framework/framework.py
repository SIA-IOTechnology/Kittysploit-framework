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
from core.module_search import ModuleSearchFilters
from core.debug_manager import DebugManager
from core.config import Config
from core.charter_manager import CharterManager
from core.encryption_manager import EncryptionManager
from core.framework.shell import ShellManager
from core.plugin_manager import PluginManager
from core.utils.validate import validate_module_type
from core.framework.utils.metrics import MetricsCollector
from core.observability.manager import ObservabilityManager
from core.framework.utils.hooks import HookManager, HookPoint
from core.framework.runtime import RuntimeKernel, EventBus, EventType
from core.framework.runtime.extension_contract import ExtensionRegistry
from core.framework.runtime.pipeline import Pipeline, PipelineStepType
from core.framework.runtime.hot_reload import HotReloadManager
from core.tor_manager import TorManager
from core.interactive_input_manager import InteractiveInputManager
import os
import importlib.util
import sys
import time
from datetime import datetime
from pathlib import Path


class Framework:
    def __init__(self, clean_sessions: bool = True):
        self.modules: Dict[str, Any] = {}
        self.current_module: Optional[Any] = None
        self.current_workflow: Optional[Any] = None
        self.version = Config.VERSION
        self.session = Session()
        self.module_loader = ModuleLoader()
        self.output_handler = OutputHandler()
        self.shell_manager = ShellManager()
        self.metrics_collector = MetricsCollector()
        self.observability = ObservabilityManager(self.metrics_collector)
        self.hook_manager = HookManager()
        
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
        
        # Initialize Tor Manager
        self.tor_manager = TorManager(framework=self)
        
        # Load Tor configuration from config if available
        tor_config = config_instance.get_config_value('tor')
        if tor_config and tor_config.get('enabled', False):
            # Auto-enable Tor if configured
            self.tor_manager.enable(
                host=tor_config.get('socks_host', '127.0.0.1'),
                socks_port=tor_config.get('socks_port'),
                control_port=tor_config.get('control_port'),
                check_availability=False  # Don't check on startup, will be checked when actually used
            )
        
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
        self.module_sync_manager.module_loader = self.module_loader
        
        # Initialize NOP manager
        self.nops = NopManager()
        
        # Initialize route manager for pivot routing
        from lib.pivot.route_manager import RouteManager
        self.route_manager = RouteManager(framework=self)
        
        # Initialize debug manager
        self.debug_manager = DebugManager()
        # Interactive input manager (for web terminal -> plugin routing, e.g. minicom)
        self.interactive_input_manager = InteractiveInputManager()
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
        
        # Initialize Guardian Manager
        try:
            from core.guardian_manager import GuardianManager
            self.guardian_manager = GuardianManager()
        except Exception as e:
            # Si le Guardian n'est pas disponible, on continue sans
            self.guardian_manager = None
            if hasattr(self, 'output_handler'):
                self.output_handler.print_warning(f"Guardian Manager not available: {e}")

        try:
            from core.scope_manager import ScopeManager
            self.scope_manager = ScopeManager(self.current_workspace)
        except Exception as e:
            self.scope_manager = None
            if hasattr(self, 'output_handler'):
                self.output_handler.print_warning(f"Scope Manager not available: {e}")
        
        # Initialize workspaces
        self._init_workspaces()

        try:
            self.observability.configure(workspace=self.current_workspace)
        except Exception as exc:
            self.output_handler.print_warning(f"Observability setup skipped: {exc}")
        
        self.current_collab: Optional[Any] = None
    
    def notify_session_disconnected(
        self,
        session_id: str,
        *,
        reason: str = "connection_lost",
        label: str = "",
        connection_token: str = "",
    ) -> None:
        """Global disconnect alert for socket-backed sessions."""
        import time
        from core.output_handler import print_warning
        from core.framework.runtime.events import EventType

        session = self.session_manager.get_session(session_id)
        if session and connection_token:
            listener_id = (session.data or {}).get("listener_id")
            listener = (getattr(self, "active_listeners", None) or {}).get(listener_id)
            if listener:
                current = getattr(listener, "_session_connections", {}).get(session_id)
                current_token = getattr(current, "connection_id", None)
                if current_token and current_token != connection_token:
                    return

        protocol = "unknown"
        implant_id = label
        if session and session.data:
            protocol = session.data.get("protocol") or session.data.get("connection_type") or protocol
            implant_id = session.data.get("implant_id") or session.data.get("client_id") or implant_id
            if session.data.get("transport_state") == "disconnected" and reason == "connection_lost":
                self._detach_shell_connection(session_id)
                return

        print_warning(
            f"Session {session_id[:8]} disconnected "
            f"({protocol}{f', implant {implant_id}' if implant_id else ''}) — {reason}"
        )

        if session:
            self.session_manager.update_session_data(
                session_id,
                {
                    "transport_state": "disconnected",
                    "disconnected_at": time.time(),
                },
            )

        self._cleanup_listener_transport(session_id, close_socket=False)

        if hasattr(self, "event_bus") and self.event_bus:
            self.event_bus.publish(
                EventType.SESSION_CLOSED,
                {
                    "session_id": session_id,
                    "reason": reason,
                    "protocol": protocol,
                    "implant_id": implant_id,
                },
                source="connection_watchdog",
            )

        self._detach_shell_connection(session_id)

    def notify_session_reconnected(
        self,
        session_id: str,
        *,
        label: str = "",
    ) -> None:
        import time
        from core.output_handler import print_success
        from core.framework.runtime.events import EventType

        session = self.session_manager.get_session(session_id)
        implant_id = label
        if session and session.data:
            implant_id = session.data.get("implant_id") or session.data.get("client_id") or implant_id

        print_success(
            f"Session {session_id[:8]} reconnected"
            f"{f' (implant {implant_id})' if implant_id else ''}"
        )

        if hasattr(self, "event_bus") and self.event_bus:
            self.event_bus.publish(
                EventType.SESSION_RECONNECTED,
                {
                    "session_id": session_id,
                    "implant_id": implant_id,
                },
                source="listener",
            )

        shell = self.shell_manager.get_shell(session_id)
        if shell:
            refresh = getattr(shell, "_refresh_connection", None)
            if callable(refresh):
                try:
                    refresh()
                except Exception:
                    pass
            normalize = getattr(shell, "_normalize_connection", None)
            if callable(normalize):
                try:
                    normalize()
                except Exception:
                    pass

    def _cleanup_listener_transport(self, session_id: str, *, close_socket: bool = True) -> None:
        session = self.session_manager.get_session(session_id)
        if not session:
            return
        listener_id = (session.data or {}).get("listener_id")
        listener = (getattr(self, "active_listeners", None) or {}).get(listener_id)
        if listener and hasattr(listener, "remove_session_connection"):
            listener.remove_session_connection(session_id, close_socket=close_socket)

    def _detach_shell_connection(self, session_id: str) -> None:
        shell = self.shell_manager.get_shell(session_id)
        if not shell:
            return
        if hasattr(shell, "connection"):
            shell.connection = None
        normalize = getattr(shell, "_normalize_connection", None)
        if callable(normalize):
            try:
                normalize()
            except Exception:
                pass
    
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

        Prefer filesystem discovery via the module loader. ``self.modules`` is only
        populated in legacy/core-load modes and is often empty after a normal boot.
        """
        if isinstance(self.modules, dict) and self.modules:
            # Legacy nested/core shape: flatten path→file when values look like file paths.
            flat: Dict[str, Any] = {}
            for key, value in self.modules.items():
                if isinstance(value, str) and value.endswith(".py"):
                    flat[str(key)] = value
                elif isinstance(value, dict):
                    for nested_key, nested_value in value.items():
                        flat[str(nested_key)] = nested_value
            if flat:
                return flat
            # Non-empty but not a path map (e.g. type→list placeholders) — fall through.
        if getattr(self, "module_loader", None) is not None:
            try:
                return self.module_loader.discover_modules()
            except Exception:
                pass
        return self.modules if isinstance(self.modules, dict) else {}
    
    def get_available_exploits(self) -> Dict[str, Any]:
        """
        Retourne tous les exploits disponibles.
        
        Returns:
            Dict[str, Any]: Exploits disponibles
        """
        return self.modules['exploits']
    
    
    def load_core_modules(self) -> None:
        try:
            # Charger uniquement les modules de base
            core_modules = {
                'scanner': [],
                'auxiliary': [],
                'exploits': []
            }
            self.modules = core_modules
            
            # Initialiser la base de données des modules
            self._init_modules_db()
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors du chargement des modules de base: {str(e)}")
    
    def _init_modules_db(self) -> None:
        try:
            # S'assurer que la contrainte de la table est à jour avant de charger les modules
            workspace_name = self.get_current_workspace_name()
            try:
                self.db_manager.migrate_modules_table_constraint(workspace_name)
            except Exception as migration_error:
                # Si la migration échoue, continuer quand même (la table sera créée avec le bon schéma si elle n'existe pas)
                self.output_handler.print_warning(f"Could not migrate database constraint: {migration_error}")
            
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
        try:
            # Mapping des dossiers vers les types de modules
            # Format: (dossier, type_module)
            module_dir_mappings = [
                ('modules/exploits', 'exploits'),
                ('modules/auxiliary', 'auxiliary'),
                ('modules/scanners', 'scanner'),
                ('modules/scanner', 'scanner'),  # Variante possible
                ('modules/workflow', 'workflow'),
                ('modules/listeners', 'listeners'),
                ('modules/browser_exploits', 'browser_exploits'),
                ('modules/browser_auxiliary', 'browser_auxiliary'),
                ('modules/docker_environments', 'docker_environment'),
                ('modules/post', 'post'),
                ('modules/payloads', 'payloads'),
                ('modules/encoders', 'encoders'),
                ('modules/transforms', 'transforms'),
                ('modules/backdoors', 'backdoors'),
                ('modules/shortcut', 'shortcut'),
                ('modules/analysis', 'analysis'),
            ]
            
            for module_dir, module_type in module_dir_mappings:
                if not os.path.exists(module_dir):
                    continue
                    
                for root, _, files in os.walk(module_dir):
                    for file in files:
                        if file.endswith('.py') and not file.startswith('__'):
                            module_path = os.path.join(root, file)
                            module_info = self.module_loader.get_module_info(module_path)
                            
                            if module_info:
                                # Créer une entrée dans la base de données
                                # Utiliser le type mappé plutôt que le nom du dossier
                                module = Module(
                                    name=module_info.get('name', ''),
                                    description=module_info.get('description', ''),
                                    type=module_type,  # Utiliser le type mappé
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
        Fusionne les résultats de la base de données avec ceux du système de fichiers
        pour garantir que tous les types de modules sont comptabilisés.
        
        Returns:
            Dict[str, int]: Dictionnaire avec le type de module comme clé et le nombre comme valeur
        """
        try:
            # Types de modules supportés
            module_types = ['exploits', 'auxiliary', 'payloads', 'encoders', 'transforms', 'listeners', 'backdoors', 'workflow', 'browser_exploits', 'browser_auxiliary', 'docker_environment', 'environments', 'post', 'scanner', 'shortcut', 'analysis']
            counts = {}
            
            # Récupérer les comptages depuis la base de données
            session = self.get_db_session()
            if session:
                try:
                    for module_type in module_types:
                        count = session.query(Module).filter_by(type=module_type, is_active=True).count()
                        if count > 0:
                            counts[module_type] = count
                    for legacy_type in ('transform', 'obfuscator'):
                        count = session.query(Module).filter_by(type=legacy_type, is_active=True).count()
                        if count > 0:
                            counts[legacy_type] = counts.get(legacy_type, 0) + count
                except Exception as db_error:
                    # Si erreur de base de données (schéma obsolète), ignorer et continuer avec filesystem
                    pass
            
            # Toujours compter depuis les fichiers pour compléter/remplacer les données DB
            # Cela garantit que les types non enregistrés en DB sont quand même comptés
            filesystem_counts = self._count_modules_from_files()
            
            # Fusionner les résultats : filesystem prend priorité car il est plus complet
            for module_type, count in filesystem_counts.items():
                counts[module_type] = count
            
            # Ajouter le nombre de plugins (toujours depuis le plugin_manager)
            if hasattr(self, 'plugin_manager') and self.plugin_manager:
                plugin_count = len(self.plugin_manager.list_plugins())
                if plugin_count > 0:
                    counts['plugins'] = plugin_count

            return self._normalize_module_count_keys(counts)
            
        except Exception as e:
            self.output_handler.print_error(f"Erreur lors du comptage des modules par type: {str(e)}")
            return {}
    
    def _normalize_module_count_keys(self, counts: Dict[str, int]) -> Dict[str, int]:
        normalized = dict(counts or {})
        legacy_transform_total = 0
        for legacy_key in ('obfuscator', 'transform'):
            legacy_transform_total += int(normalized.pop(legacy_key, 0) or 0)
        if legacy_transform_total:
            # Filesystem discovery may already populate 'transforms'; never double-count DB legacy rows.
            current = int(normalized.get('transforms', 0) or 0)
            normalized['transforms'] = max(current, legacy_transform_total)
        return normalized
    
    def _count_modules_from_files(self) -> Dict[str, int]:
        """
        Compte les modules depuis les fichiers (fallback si la base de données n'est pas disponible).
        
        Returns:
            Dict[str, int]: Dictionnaire avec le type de module comme clé et le nombre comme valeur
        """
        try:
            counts = {}
            try:
                import modules as _mod
                modules_path = os.path.dirname(os.path.abspath(_mod.__file__))
            except ImportError:
                modules_path = "modules"

            if not os.path.exists(modules_path):
                return counts
            
            # Types de modules supportés
            module_types = ['exploits', 'auxiliary', 'payloads', 'encoders', 'transforms', 'listeners', 'backdoors', 'workflow', 'browser_exploits', 'browser_auxiliary', 'docker_environment', 'environments', 'post', 'scanner', 'shortcut', 'analysis']
            
            for module_type in module_types:
                # Map module_type to directory name
                if module_type == 'docker_environment':
                    type_path = os.path.join(modules_path, 'docker_environments')
                else:
                    type_path = os.path.join(modules_path, module_type)

                if module_type == 'workflow' and getattr(self, 'module_loader', None):
                    discovered = self.module_loader.discover_modules()
                    count = sum(1 for path in discovered if path.startswith('workflow/'))
                    if count > 0:
                        counts[module_type] = count
                    continue

                if module_type == 'transforms' and getattr(self, 'module_loader', None):
                    discovered = self.module_loader.discover_modules()
                    count = sum(1 for path in discovered if path.startswith('transforms/'))
                    if count > 0:
                        counts[module_type] = count
                    continue
                
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
                # When switching to a listener after a payload that uses this listener, propagate platform so shell shows correct prompt
                prev = self.current_module
                if prev and getattr(prev, 'type', None) == 'payload':
                    prev_info = getattr(prev, '__info__', None) or {}
                    listener_path = prev_info.get('listener') or ''
                    if listener_path and module_path == listener_path and getattr(module, 'type', None) == 'listener':
                        pl = prev_info.get('platform')
                        if pl is not None:
                            platform_str = getattr(pl, 'value', None) or str(pl).lower()
                            if platform_str:
                                setattr(module, 'session_platform', platform_str)
                        use_pty = getattr(prev, 'use_pty', None)
                        if use_pty is not None:
                            pty_val = use_pty.value if hasattr(use_pty, 'value') else use_pty
                            setattr(module, 'session_pty_mode', bool(pty_val))
                        for opt_name, attr in (
                            ('encrypt', 'session_relay_encrypt'),
                            ('relay_psk', 'session_relay_psk'),
                            ('keepalive_interval', 'session_relay_keepalive'),
                        ):
                            opt = getattr(prev, opt_name, None)
                            if opt is not None:
                                val = opt.value if hasattr(opt, 'value') else opt
                                setattr(module, attr, val)
                                if hasattr(module, 'set_option'):
                                    try:
                                        module.set_option(opt_name, val)
                                    except Exception:
                                        pass
                                elif hasattr(module, opt_name):
                                    target_opt = getattr(module, opt_name)
                                    if hasattr(target_opt, 'value'):
                                        target_opt.value = val
                        relay_token = getattr(prev, 'relay_token', None)
                        if relay_token is not None and hasattr(module, 'relay_token'):
                            tok_val = relay_token.value if hasattr(relay_token, 'value') else relay_token
                            try:
                                module.set_option('relay_token', tok_val)
                            except Exception:
                                if hasattr(module.relay_token, 'value'):
                                    module.relay_token.value = tok_val
                        identity = getattr(prev, '_implant_identity_obj', None)
                        pub = getattr(prev, '_implant_public_key_pem', None)
                        if identity is not None:
                            setattr(module, 'session_implant_id', identity.implant_id)
                        if pub:
                            setattr(module, 'session_implant_public_key', pub)
                            if hasattr(module, 'set_option'):
                                try:
                                    module.set_option('implant_public_key', pub)
                                except Exception:
                                    pass
                self.current_module = module
                
                # Enregistrer pour hot reload
                module_file = os.path.join(self.module_loader.modules_path, module_path.replace("/", os.sep) + ".py")
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
    
    def execute_module(
        self,
        use_runtime_kernel: bool = True,
        skip_scope_confirm: bool = False,
    ) -> Any:
        """
        Exécute le module actuellement chargé.

        Args:
            use_runtime_kernel: Si True, utilise le Runtime Kernel pour l'exécution avec sandbox
            skip_scope_confirm: Si True, ignore la confirmation des actions destructives (scope)

        Returns:
            Any: Résultat de l'exécution du module ou False en cas d'erreur
        """
        from core.framework.module_executor import (
            ModuleExecutionBlockReason,
            ModuleExecutionRequest,
            ModuleExecutor,
        )

        if not self.current_module:
            self.output_handler.print_warning("Tentative d'exécution sans module chargé")
            return False

        if not use_runtime_kernel and self.debug_manager.is_active:
            blocked_actions = [
                action
                for action in self.debug_manager.actions
                if action.type == "module_execute_start" and action.blocked
            ]
            if blocked_actions:
                latest_blocked = max(blocked_actions, key=lambda item: item.timestamp)
                self.debug_manager.add_action(
                    "module_execute_blocked",
                    f"Module execution blocked: {getattr(self.current_module, 'name', 'unknown')}",
                    {
                        "module": getattr(self.current_module, "name", "unknown"),
                        "blocked_action_id": latest_blocked.id,
                    },
                )
                return False

            self.debug_manager.add_action(
                "module_execute_start",
                f"Starting execution of module: {getattr(self.current_module, 'name', 'unknown')}",
                {"module_path": getattr(self.current_module, "__module__", "unknown")},
            )

        guardian = getattr(self, "guardian_manager", None)
        verbose_guardian = bool(
            guardian and guardian.enabled and getattr(guardian, "verbose", False)
        )

        request = ModuleExecutionRequest(
            module=self.current_module,
            use_runtime_kernel=use_runtime_kernel,
            use_exploit_wrapper=False,
            skip_scope_confirm=skip_scope_confirm,
            collect_metrics=not use_runtime_kernel,
            verbose_guardian_debug=verbose_guardian,
        )
        execution = ModuleExecutor.execute(self, request)

        if execution.blocked:
            if execution.block_reason == ModuleExecutionBlockReason.MISSING_OPTIONS:
                if execution.missing_options:
                    self.output_handler.print_error(
                        "Exécution impossible: options requises manquantes: "
                        f"{', '.join(execution.missing_options)}"
                    )
                else:
                    self.output_handler.print_error(
                        "Exécution impossible: toutes les options requises ne sont pas définies"
                    )
                if self.debug_manager.is_active:
                    self.debug_manager.add_action(
                        "module_execute_failed",
                        "Module execution failed: missing required options",
                        {"module": getattr(self.current_module, "name", "unknown")},
                    )
            return False

        if execution.error and not execution.success:
            self.output_handler.print_error(
                f"Erreur lors de l'exécution du module: {execution.error}"
            )
            if self.debug_manager.is_active:
                self.debug_manager.add_action(
                    "module_execute_error",
                    f"Module execution error: {getattr(self.current_module, 'name', 'unknown')}",
                    {
                        "module": getattr(self.current_module, "name", "unknown"),
                        "error": execution.error,
                    },
                )
            return False

        if execution.success and self.debug_manager.is_active:
            self.debug_manager.add_action(
                "module_execute_success",
                f"Module executed successfully: {getattr(self.current_module, 'name', 'unknown')}",
                {
                    "module": getattr(self.current_module, "name", "unknown"),
                    "result": str(execution.result),
                },
            )

        if execution.success:
            return execution.result
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
        return self.module_loader.get_module_info(module_path)

    def load_all_plugins(self) -> None:
        """Charge tous les plugins disponibles (deprecated - plugins are now loaded on demand)"""
        # Plugins are now loaded on demand when executed
        # This method is kept for backward compatibility but does nothing
        pass

    def _init_workspaces(self) -> None:
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

            if hasattr(self, 'session_manager') and self.session_manager:
                self.session_manager.reload_for_current_workspace()

            if hasattr(self, 'scope_manager') and self.scope_manager:
                self.scope_manager.set_workspace(name)

            if hasattr(self, 'observability') and self.observability:
                self.observability.update_workspace(name)
        
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
        return self.proxy_config.copy()
    
    def is_proxy_enabled(self) -> bool:
        return self.proxy_config['enabled']
    
    def _extract_target_ip_from_module(self) -> Optional[str]:
        """
        Extrait l'IP cible du module actuel depuis ses options.
        
        Returns:
            str: L'IP cible si trouvée, None sinon
        """
        if not self.current_module:
            return None
        
        import re
        from urllib.parse import urlparse
        
        # Liste des noms d'options possibles pour l'IP cible
        target_option_names = ['target', 'rhost', 'rhosts', 'host', 'hostname', 'ip', 'RHOST', 'RHOSTS', 'HOST']
        
        # Essayer de récupérer depuis les attributs du module (les options sont des descripteurs)
        for attr_name in target_option_names:
            try:
                # Vérifier si l'attribut existe dans la classe ou l'instance
                if hasattr(self.current_module, attr_name):
                    # Obtenir la valeur via getattr (cela appellera __get__ du descripteur si c'est une Option)
                    value = getattr(self.current_module, attr_name)
                    
                    # Si c'est une Option (descripteur), la valeur peut être dans _instance_values
                    if value and not isinstance(value, str):
                        # Essayer d'accéder à la valeur réelle via le descripteur
                        option_descriptor = getattr(type(self.current_module), attr_name, None)
                        if option_descriptor and hasattr(option_descriptor, '_instance_values'):
                            instance_id = id(self.current_module)
                            if instance_id in option_descriptor._instance_values:
                                stored_value = option_descriptor._instance_values[instance_id]
                                # La valeur peut être dans 'value' ou 'display_value'
                                value = stored_value.get('value') or stored_value.get('display_value') or value
                    
                    # Convertir en string et extraire l'IP
                    if value:
                        value_str = str(value).strip()
                        if value_str and value_str.lower() != 'none':
                            ip = self._extract_ip_from_value(value_str)
                            if ip:
                                # Debug log seulement si Guardian est activé et verbose
                                if (hasattr(self, 'guardian_manager') and self.guardian_manager and 
                                    self.guardian_manager.enabled and self.guardian_manager.verbose and
                                    hasattr(self, 'output_handler') and self.output_handler):
                                    self.output_handler.print_info(f"[GUARDIAN DEBUG] Found IP {ip} from option {attr_name} = {value_str}")
                                return ip
            except Exception as e:
                # Log l'erreur pour débogage seulement si Guardian est activé et verbose
                if (hasattr(self, 'guardian_manager') and self.guardian_manager and 
                    self.guardian_manager.enabled and self.guardian_manager.verbose and
                    hasattr(self, 'output_handler') and self.output_handler):
                    self.output_handler.print_info(f"[GUARDIAN DEBUG] Error accessing {attr_name}: {e}")
                continue
        
        return None
    
    def _extract_ip_from_value(self, value: str) -> Optional[str]:
        """
        Extrait une adresse IP depuis une valeur qui peut être une URL, une IP, etc.
        
        Args:
            value: La valeur à analyser
            
        Returns:
            str: L'IP extraite ou None
        """
        import re
        from urllib.parse import urlparse
        
        if not value:
            return None
        
        # Pattern pour une adresse IP (IPv4)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # Si c'est une URL, extraire le hostname
        if '://' in value or value.startswith('http') or value.startswith('https'):
            try:
                parsed = urlparse(value if '://' in value else f'http://{value}')
                hostname = parsed.hostname
                if hostname:
                    # Vérifier si le hostname est une IP
                    match = re.search(ip_pattern, hostname)
                    if match:
                        return match.group(0)
                    # Sinon, essayer de résoudre (mais on ne le fait pas ici pour éviter les dépendances)
                    # Pour l'instant, on retourne None si ce n'est pas une IP directe
            except:
                pass
        
        # Chercher une IP directement dans la valeur (même si c'est une URL malformée)
        match = re.search(ip_pattern, value)
        if match:
            return match.group(0)
        
        return None
    
    def get_proxy_url(self) -> Optional[str]:
        if self.proxy_config['enabled']:
            return self.proxy_config['http_proxy']
        return None
    
    # Tor Network Methods
    
    def enable_tor(self, host: str = '127.0.0.1', socks_port: int = None, 
                   control_port: int = None, check_availability: bool = True, 
                   save_config: bool = True) -> bool:
        """
        Enable Tor network for all framework network operations
        
        Args:
            host: Tor SOCKS proxy host (default: 127.0.0.1)
            socks_port: Tor SOCKS proxy port (default: 9050, auto-detect if None)
            control_port: Tor Control port (default: 9051)
            check_availability: Whether to check if Tor is available before enabling
            save_config: Whether to save Tor configuration to config file
            
        Returns:
            True if Tor was enabled successfully, False otherwise
        """
        result = self.tor_manager.enable(host, socks_port, control_port, check_availability)
        if result and save_config:
            self.save_tor_config()
        return result
    
    def disable_tor(self, save_config: bool = True):
        """
        Disable Tor network
        
        Args:
            save_config: Whether to save Tor configuration to config file
        """
        self.tor_manager.disable()
        if save_config:
            self.save_tor_config()
    
    def is_tor_enabled(self) -> bool:
        """Check if Tor network is enabled"""
        return self.tor_manager.is_enabled()
    
    def get_tor_status(self) -> Dict[str, Any]:
        """
        Get Tor network status information
        
        Returns:
            Dictionary with Tor status information
        """
        return self.tor_manager.get_status()
    
    def check_tor_available(self, host: str = None, port: int = None) -> bool:
        """
        Check if Tor SOCKS proxy is available
        
        Args:
            host: Tor SOCKS proxy host (default: 127.0.0.1)
            port: Tor SOCKS proxy port (default: 9050)
            
        Returns:
            True if Tor is available, False otherwise
        """
        return self.tor_manager.check_tor_available(host, port)
    
    def save_tor_config(self):
        """
        Save Tor configuration to config file
        
        This saves the current Tor settings to the framework's configuration file
        so they persist across restarts.
        """
        try:
            config_instance = Config.get_instance()
            config = config_instance.get_config()
            
            # Get current Tor status
            tor_status = self.tor_manager.get_status()
            
            # Update Tor config
            if 'tor' not in config:
                config['tor'] = {}
            
            config['tor']['enabled'] = tor_status['enabled']
            config['tor']['socks_host'] = tor_status['socks_host']
            config['tor']['socks_port'] = tor_status['socks_port']
            config['tor']['control_host'] = tor_status['control_host']
            config['tor']['control_port'] = tor_status['control_port']
            
            # Save to file if config file exists and is writable
            config_path = Path(config_instance.config_file)
            if config_path.exists() and os.access(config_path, os.W_OK):
                try:
                    import tomllib
                    # For now, we'll just update the in-memory config
                    # The actual file writing would require a TOML writer
                    # which is not always available. The config will be saved
                    # when the framework saves its config through other means.
                    config_instance.config = config
                except Exception:
                    # If TOML writing fails, at least update in-memory config
                    config_instance.config = config
        except Exception as e:
            if hasattr(self, 'output_handler'):
                self.output_handler.print_warning(f"Could not save Tor configuration: {e}")
    
    # Module Synchronization Methods
    
    def start_module_sync(self, interval: int = 300):
        """Start background module synchronization"""
        self.module_sync_manager.start_background_sync(interval)
    
    def stop_module_sync(self):
        """Stop background module synchronization"""
        self.module_sync_manager.stop_background_sync()
    
    def sync_modules_now(self) -> Dict[str, int]:
        return self.module_sync_manager.sync_modules(force=True)

    def invalidate_module_caches(self, module_path: Optional[str] = None) -> None:
        """Invalidate module discovery/loader caches after sync, marketplace, or reload."""
        self.module_loader.invalidate_caches(module_path=module_path)
    
    def get_module_sync_status(self) -> Dict:
        return self.module_sync_manager.get_sync_status()
    
    def search_modules_db(
        self,
        filters: ModuleSearchFilters = None,
        query: str = "",
        module_type: str = "",
        author: str = "",
        cve: str = "",
        tags: str = "",
        limit: int = 100,
        **kwargs,
    ) -> List[Dict]:
        """Search modules in database (faster than filesystem search)."""
        if filters is None:
            filters = ModuleSearchFilters(
                query=query,
                module_type=module_type,
                author=author,
                cve=cve,
                tag=tags,
                limit=limit,
                platform=str(kwargs.get("platform") or ""),
                protocol=str(kwargs.get("protocol") or ""),
                reliability=str(kwargs.get("reliability") or ""),
                since=kwargs.get("since"),
                until=kwargs.get("until"),
            )
        return self.module_loader.search_modules_db(filters=filters)
    
    def get_module_stats_db(self) -> Dict[str, int]:
        """Get module statistics from database"""
        return self.module_loader.get_module_stats_db()
    
    # Browser Server Methods
    
    def set_browser_server(self, browser_server):
        self.browser_server = browser_server
    
    def get_browser_server(self):
        return self.browser_server
    
    def has_browser_server(self) -> bool:
        """Check if browser server is available"""
        return self.browser_server is not None
