#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Command registry for managing and loading commands dynamically
"""

import os
import importlib
import inspect
import time
from datetime import datetime
from typing import Dict, List, Type, Any
from interfaces.command_system.base_command import BaseCommand
from core.utils.exceptions import KittyException
from core.history_manager import HistoryManager

class CommandRegistry:
    """Registry for managing commands"""
    
    def __init__(self, framework, session, output_handler):
        self.framework = framework
        self.session = session
        self.output_handler = output_handler
        self.commands: Dict[str, BaseCommand] = {}
        self.command_classes: Dict[str, Type[BaseCommand]] = {}
        self.command_history: List[Dict[str, Any]] = []
        
        # Initialize history manager
        # Get workspace ID from name
        workspace_id = None
        try:
            if hasattr(framework, 'workspace_manager'):
                current_workspace = framework.workspace_manager.get_current_workspace()
                workspace_id = current_workspace.id if current_workspace else None
        except:
            pass
        
        self.history_manager = HistoryManager(framework.db_manager, workspace_id, framework)
        
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
            'history',
            'plugin',
            'generate',
            'host',
            'vuln',
            'jobs',
            'check',
            'sound',
            'pattern',
            'reset',
            'syscall',
            'collab_share_module',
            'collab_sync_module',
            'collab_edit_module',
            'collab_sync_edit',
            'environments',
            'irc',
            'reload',
            'portal',
            'scanner',
            'tor'
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
                print(f"Warning: Could not import {command_name}: {e}")
                continue
            except Exception as e:
                print(f"Error loading {command_name}: {e}")
                continue
    
    def _load_command_history(self):
        """Load command history from database"""
        try:
            # Try to load recent history from database
            if hasattr(self, 'history_manager') and self.history_manager:
                db_history = self.history_manager.get_history(limit=1000)
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
                            except:
                                timestamp = time.time()
                        
                        self.command_history.append({
                            'timestamp': timestamp,
                            'command': entry.get('command', ''),
                            'success': entry.get('success', True),
                            'args': entry.get('args', [])
                        })
                    return
        except Exception as e:
            # If loading fails, start with empty history
            pass
        
        # Ensure command_history is initialized as a list
        if not hasattr(self, 'command_history') or self.command_history is None:
            self.command_history = []
    
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
                    print(f"Warning: Could not load custom command {module_name}: {e}")
    
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
        if command_name not in self.command_classes:
            raise KittyException(f"Unknown command: '{command_name}'")
        
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
    
    def get_command_help(self, command_name: str = None) -> str:
        """
        Get help text for a command or all commands
        
        Args:
            command_name: Specific command name, or None for all commands
            
        Returns:
            str: Help text
        """
        if command_name:
            if command_name not in self.command_classes:
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
            # Create command string
            command_str = command_name
            if args:
                command_str += " " + " ".join(args)
            
            # Create history entry
            history_entry = {
                'timestamp': time.time(),
                'command': command_str,
                'success': success,
                'args': args
            }
            
            # Always add to local list first for immediate access
            if self.command_history is None:
                self.command_history = []
            
            self.command_history.append(history_entry)
            
            # Keep only last 100 entries in memory
            if len(self.command_history) > 100:
                self.command_history = self.command_history[-100:]
            
            # Try to add to database (but don't fail if it doesn't work)
            try:
                if hasattr(self, 'history_manager') and self.history_manager:
                    self.history_manager.add_command(command_str, args, success)
            except Exception as db_error:
                # Database recording failed, but local history is saved
                # This is fine - we have the local history as backup
                pass
                
        except Exception as e:
            # If recording fails completely, log but continue
            # Don't print error to avoid cluttering output
            pass
