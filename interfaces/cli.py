#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.application import get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.filters import Condition

from core.session import Session
from core.output_handler import OutputHandler, print_info, print_error, print_status
from interfaces.command_system.command_registry import CommandRegistry
from interfaces.command_system.advanced_completer import AdvancedCompleter
from core.config import Config


class CommandAutoSuggest(AutoSuggest):
    """Inline suggestions driven by the advanced completer."""

    def __init__(self, completer: AdvancedCompleter):
        self.completer = completer

    def get_suggestion(self, buffer, document):
        # Avoid suggestions on empty input to keep the prompt quiet.
        if not document.text_before_cursor.strip():
            return None

        try:
            completions = list(self.completer.get_completions(document, None))
        except Exception:
            return None

        if not completions:
            return None

        first = completions[0]
        word = document.get_word_before_cursor(WORD=True)

        if document.text_before_cursor.endswith(' '):
            suggestion_text = first.text
        else:
            suggestion_text = first.text[len(word):]

        if suggestion_text:
            return Suggestion(suggestion_text)
        return None

class CLI:
    def __init__(self, framework, quiet):
        self.framework = framework
        self.quiet = quiet
        self.session = Session()
        self.output_handler = OutputHandler()
        self.command_registry = CommandRegistry(self.framework, self.session, self.output_handler)
        self.advanced_completer = AdvancedCompleter(self.command_registry, self.framework)
        
        # Prompt history file
        history_file = os.path.expanduser('~/.kittysploit_history')
        
        # Create custom key bindings
        kb = KeyBindings()
        
        # Add a binding for F5 to refresh the prompt
        @kb.add('f5')
        def _(event):
            self.update_completer()
            get_app().invalidate()
        
        # Create the prompt session with the key bindings
        self.prompt_session = PromptSession(
            history=FileHistory(history_file),
            auto_suggest=CommandAutoSuggest(self.advanced_completer),
            enable_history_search=True,
            key_bindings=kb
        )
        
        # Prompt style
        self.style = Style.from_dict({
            'prompt': 'ansired bold',
            'path': 'ansigreen',
            'module': 'ansicyan underline',
            'sessions': 'ansigreen bold',
            'workspace': 'ansiyellow bold'
        })
        
    def update_completer(self):
        """Update the completer caches."""
        self.advanced_completer.refresh()
    
    def get_prompt(self):
        """Generate the prompt based on the current context"""
        # Get prompt name from config.toml, default to "kittysploit" if not found
        try:
            config_instance = Config.get_instance()
            framework_config = config_instance.get_config_value('FRAMEWORK') or config_instance.get_config_value('framework') or {}
            prompt_name = framework_config.get('prompt', 'kittysploit')
        except Exception:
            prompt_name = 'kittysploit'
        
        # Get the number of active sessions (standard + browser)
        if hasattr(self.framework, 'session_manager') and self.framework.session_manager:
            all_sessions = self.framework.session_manager.get_all_sessions()
            session_count = len(all_sessions.get('standard', {})) + len(all_sessions.get('browser', {}))
        else:
            session_count = 0
        
        # Get the name of the current module
        module_name = ""
        if self.framework.current_module:
            if hasattr(self.framework.current_module, 'name') and self.framework.current_module.name:
                module_name = self.framework.current_module.name
            else:
                # Fallback to the module path if the name is not defined
                module_name = self.framework.current_module.__class__.__module__.replace('modules.', '')
        
        # Get workspace information
        workspace = self.framework.get_current_workspace()
        
        # Determine which workspace to display
        if self.framework.current_collab:
            # In collaboration mode, show collaboration workspace with client count
            collab_client_count = 0
            if hasattr(self.framework, 'collab_client') and self.framework.collab_client:
                collab_client_count = len(self.framework.collab_client.get_connected_clients())
            workspace_display = f"[<workspace>collab:{self.framework.current_collab}:{collab_client_count}</workspace>]"
        else:
            # In local mode, show the local workspace
            workspace_display = f"[<workspace>{workspace}</workspace>]"
        
        # Build the prompt with the workspace, number of sessions and the current module
        if module_name:
            return HTML(f"{workspace_display} {prompt_name} <sessions>[{session_count}]</sessions> (<module>{module_name}</module>)> ")
        else:
            return HTML(f"{workspace_display} {prompt_name} <sessions>[{session_count}]</sessions>> ")
    
    def start(self):
        # Check charter acceptance before starting
        if not self.framework.check_charter_acceptance():
            print_info("\n" + "="*80)
            print_info("First startup of KittySploit")
            print_info("="*80)
            if not self.framework.prompt_charter_acceptance():
                print_error("Charter not accepted. Stopping framework.")
                return
            print_info("\n" + "="*80)
        
        # Handle encryption setup/loading
        if not self.framework.is_encryption_initialized():
            print_info("\n" + "="*80)
            print_status("Encryption setup")
            print_info("="*80)
            if not self.framework.initialize_encryption():
                print_error("Failed to initialize encryption. Stopping framework.")
                return
            print_info("\n" + "="*80)
        else:
            # Load existing encryption
            if not self.framework.load_encryption():
                print_error("Failed to load encryption. Stopping framework.")
                return

        if not self.quiet:
            self.handle_command("banner")
        
        while True:
            try:
                # Update the completer to reflect the current state
                self.update_completer()
                
                # Get the user input
                user_input = self.prompt_session.prompt(
                    self.get_prompt,  # Use a function instead of a string
                    style=self.style,
                    completer=self.advanced_completer,
                    refresh_interval=2.5  # Refresh the prompt every 2.5 seconds
                )
                
                # Handle the command
                if user_input.strip():
                    self.handle_command(user_input)
                    
            except KeyboardInterrupt:
                # Ctrl+C - ignore and continue
                continue
            except EOFError:
                # Ctrl+D - quit properly
                print_info("Quitting KittySploit...")
                break
            except Exception as e:
                print_error(f"Error: {str(e)}")
    
    def handle_command(self, command_input: str):
        """
        Handle a command using the new command system
        
        Args:
            command_input: The command string to execute
        """
        if not command_input.strip():
            return
        
        parts = command_input.strip().split()
        command_name = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        try:
            # Try to execute with the new command system
            success = self.command_registry.execute_command(command_name, args, framework=self.framework)
            if not success:
                print_error(f"Command '{command_name}' failed")
        except Exception as e:
            print_error(f"Error executing command '{command_name}': {str(e)}")
