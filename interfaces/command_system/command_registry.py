#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command registry for managing and loading commands dynamically
"""

import os
import importlib
import inspect
import time
import logging
from contextlib import nullcontext
from datetime import datetime
from typing import Dict, List, Type, Any
from interfaces.command_system.base_command import BaseCommand
from core.utils.exceptions import KittyException
from core.history_manager import HistoryManager


logger = logging.getLogger(__name__)


class CommandRegistry:
    """Registry for managing commands"""
    
    def __init__(self, framework, session, output_handler):
        self.framework = framework
        self.session = session
        self.output_handler = output_handler
        self.commands: Dict[str, BaseCommand] = {}
        self.command_classes: Dict[str, Type[BaseCommand]] = {}
        self.command_aliases: Dict[str, str] = {}
        self.command_history: List[Dict[str, Any]] = []
        self._history_workspace_id = None
        
        # Initialize history manager
        # Get workspace ID from name
        workspace_id = None
        try:
            if hasattr(framework, 'workspace_manager'):
                current_workspace = framework.workspace_manager.get_current_workspace()
                workspace_id = current_workspace.id if current_workspace else None
        except Exception:
            logger.warning(
                "Unable to determine current workspace for command history; "
                "history will not be workspace-scoped",
                exc_info=True,
            )
        
        self.history_manager = HistoryManager(framework.db_manager, workspace_id, framework)
        self._history_workspace_id = self.history_manager.refresh_workspace()
        
        # Load built-in commands
        self._load_builtin_commands()
        
        # Load custom commands from commands directory
        self._load_custom_commands()
        
        # Load command history from database
        self._load_command_history()
    
    def _load_builtin_commands(self):
        """Load built-in commands"""
        builtin_commands = [
            'banner',
            'agent',
            'tuto',
            'help', 
            'clear',
            'exit',
            'use',
            'show',
            'run',
            'search',
            'set',
            'back',
            'interpreter',
            'workspace',
            'sync',
            'debug',
            'collab_server',
            'collab_connect',
            'collab_chat',
            'collab_disconnect',
            'debug_proxy',
            'proxy',
            'demo',
            'guardian',
            'market',
            'browser_server',
            'sessions',
            'shell',
            'compatible_payloads',
            'edit',
            'network_discover',
            'myip',
            'http',
            'history',
            'plugin',
            'generate',
            'host',
            'vuln',
            'jobs',
            'listen',
            'msf',
            'check',
            'doctor',
            'attack',
            'inventory',
            'lab',
            'sound',
            'pattern',
            'reset',
            'syscall',
            'detection_pack',
            'api_import',
            'new',
            'collab_share_module',
            'collab_sync_module',
            'collab_edit_module',
            'collab_sync_edit',
            'environments',
            'irc',
            'reload',
            'portal',
            'scanner',
            'tor',
            'route',
            'scope',
            'campaign',
            'workflows'
        ]
        
        for command_name in builtin_commands:
            try:
                module_name = f"interfaces.command_system.builtin.{command_name}_command"
                module = importlib.import_module(module_name)
                
                # Find the command class
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, BaseCommand) and 
                        obj != BaseCommand):
                        self.register_command(obj)
                        break
            except ImportError as e:
                # Command not found, skip
                logger.debug("Could not import built-in command %r", command_name, exc_info=True)
                print(f"Warning: Could not import {command_name}: {e}")
                continue
            except Exception as e:
                logger.exception("Error loading built-in command %r", command_name)
                print(f"Error loading {command_name}: {e}")
                continue
    
    def _load_command_history(self):
        """Load command history from database"""
        try:
            # Try to load recent history from database
            if hasattr(self, 'history_manager') and self.history_manager:
                self._history_workspace_id = self.history_manager.refresh_workspace()
                from core.history_manager import MAX_HISTORY_ENTRIES

                db_history = self.history_manager.get_history(limit=MAX_HISTORY_ENTRIES)
                if db_history:
                    # Convert database format to local format
                    self.command_history = []
                    for entry in db_history:
                        # Convert ISO timestamp to Unix timestamp if needed
                        timestamp = entry.get('timestamp', time.time())
                        if isinstance(timestamp, str):
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                timestamp = dt.timestamp()
                            except (TypeError, ValueError):
                                logger.debug(
                                    "Invalid command history timestamp %r; using current time",
                                    timestamp,
                                    exc_info=True,
                                )
                                timestamp = time.time()
                        
                        self.command_history.append({
                            'timestamp': timestamp,
                            'command': entry.get('command', ''),
                            'success': entry.get('success', True),
                            'args': entry.get('args', [])
                        })
                    return
        except Exception:
            logger.warning(
                "Failed to load command history from database; continuing with empty history",
                exc_info=True,
            )
        
        # Ensure command_history is initialized as a list
        if not hasattr(self, 'command_history') or self.command_history is None:
            self.command_history = []

    def refresh_history_workspace(self, reload: bool = False):
        """Refresh history workspace state after workspace switches."""
        if not hasattr(self, 'history_manager') or not self.history_manager:
            return
        current_workspace_id = self.history_manager.refresh_workspace()
        if current_workspace_id != self._history_workspace_id:
            self._history_workspace_id = current_workspace_id
            self.command_history = []
        if reload:
            self._load_command_history()
    
    def _save_command_history(self):
        """Save command history to database (no-op, handled by add_command)"""
        pass  # History is saved directly to database via add_command
    
    def _load_custom_commands(self):
        """Load custom commands from the commands directory"""
        commands_dir = os.path.join(os.path.dirname(__file__), 'custom')
        
        if not os.path.exists(commands_dir):
            return
        
        for filename in os.listdir(commands_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                try:
                    module = importlib.import_module(f"interfaces.command_system.custom.{module_name}")
                    
                    # Find command classes in the module
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, BaseCommand) and 
                            obj != BaseCommand):
                            self.register_command(obj)
                except ImportError as e:
                    logger.debug("Could not import custom command %r", module_name, exc_info=True)
                    print(f"Warning: Could not load custom command {module_name}: {e}")
                except Exception as e:
                    logger.exception("Error loading custom command %r", module_name)
                    print(f"Error loading custom command {module_name}: {e}")
    
    def register_command(self, command_class: Type[BaseCommand]):
        """
        Register a command class
        
        Args:
            command_class: Command class to register
        """
        if not issubclass(command_class, BaseCommand):
            raise KittyException(f"Command class must inherit from BaseCommand")
        
        # Create an instance to get the command name
        temp_instance = command_class(self.framework, self.session, self.output_handler)
        command_name = temp_instance.name
        
        if command_name in self.command_classes:
            raise KittyException(f"Command '{command_name}' is already registered")
        
        self.command_classes[command_name] = command_class

        for alias in temp_instance.aliases:
            if alias in self.command_classes or alias in self.command_aliases:
                raise KittyException(f"Command alias '{alias}' is already registered")
            self.command_aliases[alias] = command_name

    def resolve_command_name(self, command_name: str) -> str:
        """Resolve an alias to its primary command name."""
        return self.command_aliases.get(command_name, command_name)
    
    def get_command(self, command_name: str) -> BaseCommand:
        """
        Get a command instance
        
        Args:
            command_name: Name of the command
            
        Returns:
            BaseCommand: Command instance
            
        Raises:
            KittyException: If command is not found
        """
        original_name = command_name
        command_name = self.resolve_command_name(command_name)

        if command_name not in self.command_classes:
            raise KittyException(f"Unknown command: '{original_name}'")
        
        # Create instance if not already created
        if command_name not in self.commands:
            command_class = self.command_classes[command_name]
            self.commands[command_name] = command_class(
                self.framework, 
                self.session, 
                self.output_handler
            )
        
        return self.commands[command_name]
    
    def get_available_commands(self) -> List[str]:
        """
        Get list of available command names
        
        Returns:
            List[str]: List of command names
        """
        return list(self.command_classes.keys())

    def get_completion_command_names(self) -> List[str]:
        """Primary command names plus registered aliases (for tab completion)."""
        return sorted(set(self.command_classes.keys()) | set(self.command_aliases.keys()))
    
    def get_command_help(self, command_name: str = None) -> str:
        """
        Get help text for a command or all commands
        
        Args:
            command_name: Specific command name, or None for all commands
            
        Returns:
            str: Help text
        """
        if command_name:
            resolved_name = self.resolve_command_name(command_name)
            if resolved_name not in self.command_classes:
                return f"Unknown command: {command_name}"
            
            command = self.get_command(command_name)
            return command.help_text
        else:
            help_text = "Available commands:\n"
            help_text += "=" * 50 + "\n\n"
            
            for cmd_name in sorted(self.get_available_commands()):
                command = self.get_command(cmd_name)
                help_text += f"{cmd_name:<20} {command.description}\n"
            
            return help_text
    
    def execute_command(self, command_name: str, args: List[str], **kwargs) -> bool:
        """
        Execute a command
        
        Args:
            command_name: Name of the command to execute
            args: Command arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            bool: True if command executed successfully, False otherwise
        """
        framework = kwargs.get('framework')
        observability = getattr(framework, 'observability', None) if framework else None
        track = (
            observability.track_command(command_name, args)
            if observability and observability.enabled
            else nullcontext()
        )
        try:
            with track:
                return self._execute_command_impl(command_name, args, **kwargs)
        except Exception:
            raise

    def _execute_command_impl(self, command_name: str, args: List[str], **kwargs) -> bool:
        try:
            # Debug: Check for blocked actions first
            framework = kwargs.get('framework')
            if framework and hasattr(framework, 'debug_manager') and framework.debug_manager.is_active:
                # Check if any command_execute actions are blocked
                blocked_actions = [action for action in framework.debug_manager.actions 
                                 if action.type == "command_execute" and action.blocked]
                
                if blocked_actions:
                    # Find the most recent blocked command_execute action
                    latest_blocked = max(blocked_actions, key=lambda x: x.timestamp)
                    framework.debug_manager.add_action(
                        "command_execute_blocked",
                        f"Command execution blocked: {command_name}",
                        {"command": command_name, "args": args, "blocked_action_id": latest_blocked.id}
                    )
                    return False
                
                # If not blocked, create the action
                action_id = framework.debug_manager.add_action(
                    "command_execute",
                    f"Executing command: {command_name}",
                    {"command": command_name, "args": args}
                )
            
            command = self.get_command(command_name)
            # Pass the command registry to the command so it can access other commands
            kwargs['command_registry'] = self
            result = command.execute(args, **kwargs)
            
            # Record command in history (skip history command itself to avoid recursion)
            if command_name != 'history':
                # Ensure result is converted to boolean for history
                success = bool(result) if result is not None else False
                self._record_command_history(command_name, args, success)
                if command_name == 'workspace' and args and args[0].lower() == 'switch' and success:
                    self.refresh_history_workspace(reload=True)
            
            # Debug: Capture command result
            if framework and hasattr(framework, 'debug_manager') and framework.debug_manager.is_active:
                framework.debug_manager.add_action(
                    "command_execute_result",
                    f"Command executed: {command_name}",
                    {"command": command_name, "args": args, "result": result}
                )
            
            return result
        except KittyException as e:
            self.output_handler.print_error(str(e))
            
            # Record failed command in history
            if command_name != 'history':
                self._record_command_history(command_name, args, False)
            
            # Debug: Capture command error
            framework = kwargs.get('framework')
            if framework and hasattr(framework, 'debug_manager') and framework.debug_manager.is_active:
                framework.debug_manager.add_action(
                    "command_execute_error",
                    f"Command error: {command_name}",
                    {"command": command_name, "args": args, "error": str(e)}
                )
            return False
        except Exception as e:
            self.output_handler.print_error(f"Error executing command '{command_name}': {str(e)}")
            
            # Record failed command in history
            if command_name != 'history':
                self._record_command_history(command_name, args, False)
            
            # Debug: Capture unexpected error
            framework = kwargs.get('framework')
            if framework and hasattr(framework, 'debug_manager') and framework.debug_manager.is_active:
                framework.debug_manager.add_action(
                    "command_execute_unexpected_error",
                    f"Unexpected command error: {command_name}",
                    {"command": command_name, "args": args, "error": str(e)}
                )
            return False
    
    def _record_command_history(self, command_name: str, args: List[str], success: bool):
        """Record a command in the history"""
        import time
        try:
            self.refresh_history_workspace()

            # Create redacted command string and arguments
            if hasattr(self, 'history_manager') and self.history_manager:
                safe_record = self.history_manager.sanitize_command_parts(command_name, args)
                command_str = safe_record['command']
                safe_args = safe_record['args']
            else:
                command_str = command_name
                safe_args = list(args or [])
                if safe_args:
                    command_str += " " + " ".join(safe_args)
            
            # Create history entry
            history_entry = {
                'timestamp': time.time(),
                'command': command_str,
                'success': success,
                'args': safe_args
            }
            
            # Always add to local list first for immediate access
            if self.command_history is None:
                self.command_history = []
            
            self.command_history.append(history_entry)
            
            # Keep only last N entries in memory (matches DB retention)
            from core.history_manager import MAX_HISTORY_ENTRIES

            if len(self.command_history) > MAX_HISTORY_ENTRIES:
                self.command_history = self.command_history[-MAX_HISTORY_ENTRIES:]
            
            # Try to add to database (but don't fail if it doesn't work)
            try:
                if hasattr(self, 'history_manager') and self.history_manager:
                    persisted = self.history_manager.add_command(command_str, safe_args, success)
                    if not persisted:
                        logger.warning(
                            "History manager rejected command history entry for %r; kept in memory only",
                            command_name,
                        )
            except Exception:
                # Database recording failed, but local history is saved
                # This is fine - we have the local history as backup
                logger.warning(
                    "Failed to persist command history entry for %r; kept in memory only",
                    command_name,
                    exc_info=True,
                )
                
        except Exception:
            # If recording fails completely, log but continue
            # Don't print error to avoid cluttering output
            logger.warning(
                "Failed to record command history entry for %r",
                command_name,
                exc_info=True,
            )
