#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo Shell - A specialized shell for demonstration mode
"""

import os
import sys
from typing import Dict, List, Any, Optional
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML

from core.output_handler import print_info, print_success, print_error, print_warning, print_status, print_empty
from core.demo.session_manager import DemoSessionManager


class DemoShell:
    """Specialized shell for demo mode with limited commands"""
    
    def __init__(self, demo_manager: DemoSessionManager, demo_modules: Dict[str, Any]):
        self.demo_manager = demo_manager
        self.demo_modules = demo_modules
        
        # Create demo-specific completer
        self.completer = WordCompleter([
            'use', 'sessions', 'help', 'exit', 'back', 'modules', 'status'
        ] + list(demo_modules.keys()), ignore_case=True)
        
        # Demo shell style
        self.style = Style.from_dict({
            'prompt': 'ansiblue bold',
            'demo': 'ansiyellow bold'
        })
        
        # Create prompt session
        self.prompt_session = PromptSession(
            auto_suggest=AutoSuggestFromHistory(),
            enable_history_search=True
        )
    
    def get_prompt(self):
        """Get the demo shell prompt"""
        return HTML("<demo>(demo)</demo> ")
    
    def start(self):
        """Start the demo shell"""
        print_success("Entering demo shell mode...")
        print_info("Available commands:")
        print_info("  use <module>     - Use a demo module")
        print_info("  modules          - List available demo modules")
        print_info("  sessions         - List active sessions")
        print_info("  sessions -i <id> - Interact with session")
        print_info("  status           - Show demo status")
        print_info("  help             - Show this help")
        print_info("  exit             - Exit demo mode")
        print_info("  back             - Return to main KittySploit")
        print_empty()
        
        while True:
            try:
                # Get user input with demo-specific prompt
                user_input = self.prompt_session.prompt(
                    self.get_prompt,
                    style=self.style,
                    completer=self.completer
                )
                
                if not user_input:
                    continue
                
                parts = user_input.split()
                command = parts[0].lower()
                
                if command == 'exit':
                    self._stop_demo()
                    break
                elif command == 'back':
                    print_success("Returning to main KittySploit...")
                    break
                elif command == 'help':
                    self._show_help()
                elif command == 'modules':
                    self._list_modules()
                elif command == 'status':
                    self._show_status()
                elif command == 'use':
                    if len(parts) > 1:
                        self._use_demo_module(parts[1])
                    else:
                        print_error("Usage: use <module_name>")
                elif command == 'sessions':
                    if len(parts) > 1 and parts[1] == '-i' and len(parts) > 2:
                        session = self.demo_manager.get_session(parts[2])
                        if session:
                            self._interact_with_session(session)
                        else:
                            print_error(f"Session {parts[2]} not found")
                    else:
                        self._list_sessions()
                else:
                    print_error(f"Unknown command: {command}")
                    print_info("Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print_info("\nUse 'exit' to quit demo mode or 'back' to return to main KittySploit")
            except EOFError:
                break
    
    def _stop_demo(self):
        """Stop demo mode"""
        # Kill all sessions
        sessions = self.demo_manager.list_sessions()
        for session in sessions:
            self.demo_manager.kill_session(session['id'])
        
        self.demo_manager.demo_active = False
        print_success("Demo mode stopped")
    
    def _show_help(self):
        """Show demo help"""
        print_info("=== Demo Shell Help ===")
        print_info("Commands:")
        print_info("  use <module>     - Use a demo module")
        print_info("  modules          - List available demo modules")
        print_info("  sessions         - List active sessions")
        print_info("  sessions -i <id> - Interact with session")
        print_info("  status           - Show demo status")
        print_info("  help             - Show this help")
        print_info("  exit             - Exit demo mode")
        print_info("  back             - Return to main KittySploit")
        print_info("")
        print_info("Available modules:")
        for module_name in self.demo_modules.keys():
            print_info(f"  {module_name}")
    
    def _list_modules(self):
        """List available demo modules"""
        print_info("=== Available Demo Modules ===")
        for module_name, module_class in self.demo_modules.items():
            module_instance = module_class()
            info = module_instance.get_info()
            print_info(f"  {module_name}: {info['description']}")
    
    def _show_status(self):
        """Show demo status"""
        sessions = self.demo_manager.list_sessions()
        active = getattr(self.demo_manager, 'demo_active', False)
        
        print_info("=== Demo Status ===")
        print_info(f"Demo mode: {'Active' if active else 'Inactive'}")
        print_info(f"Active sessions: {len(sessions)}")
        print_info(f"Available modules: {len(self.demo_modules)}")
        
        if sessions:
            print_info("\nActive Sessions:")
            for session in sessions:
                print_info(f"  {session['id']}: {session['type']} ({session['user']})")
    
    def _list_sessions(self):
        """List active sessions"""
        sessions = self.demo_manager.list_sessions()
        if not sessions:
            print_info("No active sessions")
            return
        
        print_info("=== Active Sessions ===")
        print_info(f"{'ID':<10} {'Type':<12} {'User':<10} {'Root':<6} {'Hostname':<15}")
        print_info("-" * 60)
        
        for session in sessions:
            print_info(f"{session['id']:<10} {session['type']:<12} {session['user']:<10} "
                      f"{'yes' if session['is_root'] else 'no':<6} {session['hostname']:<15}")
    
    def _use_demo_module(self, module_name: str):
        """Use a demo module"""
        if module_name not in self.demo_modules:
            print_error(f"Demo module '{module_name}' not found")
            print_info("Available modules: " + ", ".join(self.demo_modules.keys()))
            return
        
        module_class = self.demo_modules[module_name]
        module_instance = module_class()
        
        # Set session manager
        if hasattr(module_instance, 'set_session_manager'):
            module_instance.set_session_manager(self.demo_manager)
        
        print_success(f"Using demo module: {module_name}")
        
        # Get module options
        info = module_instance.get_info()
        if info['options']:
            print_info("Module options:")
            for opt_name, opt_info in info['options'].items():
                current_value = module_instance.options.get(opt_name, opt_info.get('default', 'Not set'))
                print_info(f"  {opt_name}: {current_value}")
        
        # Run the module
        try:
            result = module_instance.run(module_instance.options)
            if result.get('status') == 'success':
                print_success(f"Module {module_name} completed successfully")
            else:
                print_error(f"Module {module_name} failed: {result.get('message', 'Unknown error')}")
        except Exception as e:
            print_error(f"Error running module {module_name}: {e}")
    
    def _interact_with_session(self, session):
        """Interact with a specific session"""
        print_success(f"Interacting with session {session.id}")
        print_info("Type 'exit' to return to demo shell")
        
        while True:
            try:
                prompt = session.get_prompt()
                command = input(prompt)
                
                if not command:
                    continue
                
                if command.lower() == 'exit':
                    break
                
                result = session.execute(command)
                if result.get('output'):
                    print(result['output'])
            
            except KeyboardInterrupt:
                print_info("\nUse 'exit' to return to demo shell")
            except EOFError:
                break
