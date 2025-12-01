#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo command for entering a demonstration prompt
"""

import os
import sys
import importlib
from typing import Dict, List, Any, Optional
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning, print_status, print_empty
from core.demo.session_manager import DemoSessionManager
from core.demo.base import Demo
from interfaces.command_system.demo_shell import DemoShell
import argparse


class DemoCommand(BaseCommand):
    """Command to enter a demonstration prompt with simulated modules and sessions"""
    
    @property
    def name(self) -> str:
        return "demo"
    
    @property
    def description(self) -> str:
        return "Enter a demonstration prompt with simulated modules and sessions"
    
    @property
    def usage(self) -> str:
        return "demo [start|stop|status|modules|sessions] [options]"
    
    def get_subcommands(self) -> List[str]:
        """Get available subcommands for auto-completion"""
        return ['start', 'stop', 'status', 'modules', 'sessions', 'interact']
    
    def __init__(self, framework=None, session=None, output_handler=None):
        super().__init__(framework, session, output_handler)
        self.demo_manager = None
        self.demo_modules = {}
        self._load_demo_modules()
    
    def _load_demo_modules(self):
        """Load all available demo modules"""
        demo_modules_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'core', 'demo', 'modules')
        
        if not os.path.exists(demo_modules_path):
            return
        
        for filename in os.listdir(demo_modules_path):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]
                try:
                    module_path = f"core.demo.modules.{module_name}"
                    module = importlib.import_module(module_path)
                    
                    # Find Demo class in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, Demo) and 
                            attr != Demo):
                            self.demo_modules[module_name] = attr
                            break
                except Exception as e:
                    print_warning(f"Failed to load demo module {module_name}: {e}")
    
    def _create_parser(self):
        """Create argument parser for demo command"""
        parser = argparse.ArgumentParser(
            prog='demo',
            description='Enter a demonstration prompt with simulated modules and sessions'
        )
        
        subparsers = parser.add_subparsers(dest='subcommand', help='Available subcommands')
        
        # Start subcommand
        start_parser = subparsers.add_parser('start', help='Start demo mode')
        start_parser.add_argument('--module', '-m', help='Start with specific demo module')
        start_parser.add_argument('--shell-type', choices=['bash', 'cmd', 'powershell'], 
                                default='bash', help='Default shell type for sessions')
        start_parser.add_argument('--username', default='user', help='Default username for sessions')
        start_parser.add_argument('--root', action='store_true', help='Start with root privileges')
        
        # Stop subcommand
        stop_parser = subparsers.add_parser('stop', help='Stop demo mode')
        
        # Status subcommand
        status_parser = subparsers.add_parser('status', help='Show demo status')
        
        # Modules subcommand
        modules_parser = subparsers.add_parser('modules', help='List available demo modules')
        modules_parser.add_argument('--info', help='Show detailed info for specific module')
        
        # Sessions subcommand
        sessions_parser = subparsers.add_parser('sessions', help='Manage demo sessions')
        sessions_parser.add_argument('--list', '-l', action='store_true', help='List active sessions')
        sessions_parser.add_argument('--interact', '-i', help='Interact with specific session')
        sessions_parser.add_argument('--kill', '-k', help='Kill specific session')
        
        # Interact subcommand
        interact_parser = subparsers.add_parser('interact', help='Enter interactive demo mode')
        interact_parser.add_argument('--session', '-s', help='Interact with specific session')
        
        return parser
    
    def execute(self, args, **kwargs):
        """Execute the demo command"""
        if not args:
            args = ['--help']
        
        parser = self._create_parser()
        
        try:
            parsed_args = parser.parse_args(args)
        except SystemExit:
            return True  # Help was shown successfully
        
        if not parsed_args.subcommand:
            parser.print_help()
            return False
        
        # Initialize demo manager if not already done
        if not self.demo_manager:
            self.demo_manager = DemoSessionManager()
        
        # Route to appropriate subcommand
        if parsed_args.subcommand == 'start':
            return self._start_demo(parsed_args)
        elif parsed_args.subcommand == 'stop':
            return self._stop_demo()
        elif parsed_args.subcommand == 'status':
            return self._show_status()
        elif parsed_args.subcommand == 'modules':
            return self._list_modules(parsed_args)
        elif parsed_args.subcommand == 'sessions':
            return self._manage_sessions(parsed_args)
        elif parsed_args.subcommand == 'interact':
            return self._interact_mode(parsed_args)
        
        return False
    
    def _start_demo(self, args) -> bool:
        """Start demo mode"""
        if self.demo_manager and hasattr(self.demo_manager, 'demo_active') and self.demo_manager.demo_active:
            print_warning("Demo mode is already active")
            return True
        
        print_success("Starting demo mode...")
        print_info("Demo mode provides simulated modules and sessions for demonstration purposes")
        
        # Mark demo as active
        if not hasattr(self.demo_manager, 'demo_active'):
            self.demo_manager.demo_active = True
        
        # If specific module requested, start it
        if args.module:
            return self._start_demo_module(args.module, args)
        
        # Enter demo shell mode
        demo_shell = DemoShell(self.demo_manager, self.demo_modules)
        demo_shell.start()
        return True
    
    def _stop_demo(self) -> bool:
        """Stop demo mode"""
        if not self.demo_manager or not getattr(self.demo_manager, 'demo_active', False):
            print_warning("Demo mode is not active")
            return True
        
        # Kill all sessions
        sessions = self.demo_manager.list_sessions()
        for session in sessions:
            self.demo_manager.kill_session(session['id'])
        
        self.demo_manager.demo_active = False
        print_success("Demo mode stopped")
        return True
    
    def _show_status(self) -> bool:
        """Show demo status"""
        if not self.demo_manager:
            print_info("Demo manager not initialized")
            return True
        
        active = getattr(self.demo_manager, 'demo_active', False)
        sessions = self.demo_manager.list_sessions()
        
        print_info("=== Demo Status ===")
        print_info(f"Demo mode: {'Active' if active else 'Inactive'}")
        print_info(f"Active sessions: {len(sessions)}")
        print_info(f"Available modules: {len(self.demo_modules)}")
        
        if sessions:
            print_info("\nActive Sessions:")
            for session in sessions:
                print_info(f"  {session['id']}: {session['type']} ({session['user']})")
        
        return True
    
    
    def _list_modules(self, args) -> bool:
        """List available demo modules"""
        if args.info:
            if args.info in self.demo_modules:
                module_class = self.demo_modules[args.info]
                module_instance = module_class()
                info = module_instance.get_info()
                
                print_info(f"=== {info['name']} ===")
                print_info(f"Description: {info['description']}")
                print_info(f"Path: {getattr(module_class, 'PATH', 'N/A')}")
                
                if info['options']:
                    print_info("\nOptions:")
                    for opt_name, opt_info in info['options'].items():
                        required = " (required)" if opt_info.get('required', False) else ""
                        default = f" (default: {opt_info.get('default', 'N/A')})" if 'default' in opt_info else ""
                        print_info(f"  {opt_name}: {opt_info.get('description', 'No description')}{required}{default}")
            else:
                print_error(f"Module '{args.info}' not found")
                return False
        else:
            print_info("=== Available Demo Modules ===")
            for module_name, module_class in self.demo_modules.items():
                module_instance = module_class()
                info = module_instance.get_info()
                print_info(f"  {module_name}: {info['description']}")
        
        return True
    
    def _manage_sessions(self, args) -> bool:
        """Manage demo sessions"""
        if args.list:
            sessions = self.demo_manager.list_sessions()
            if not sessions:
                print_info("No active sessions")
                return True
            
            print_info("=== Active Sessions ===")
            print_info(f"{'ID':<10} {'Type':<12} {'User':<10} {'Root':<6} {'Hostname':<15}")
            print_info("-" * 60)
            
            for session in sessions:
                print_info(f"{session['id']:<10} {session['type']:<12} {session['user']:<10} "
                          f"{'yes' if session['is_root'] else 'no':<6} {session['hostname']:<15}")
        
        elif args.interact:
            session = self.demo_manager.get_session(args.interact)
            if not session:
                print_error(f"Session {args.interact} not found")
                return False
            
            return self._interact_with_session(session)
        
        elif args.kill:
            if self.demo_manager.kill_session(args.kill):
                print_success(f"Killed session {args.kill}")
            else:
                print_error(f"Session {args.kill} not found")
                return False
        
        return True
    
    def _interact_mode(self, args) -> bool:
        """Enter interactive demo mode"""
        if not getattr(self.demo_manager, 'demo_active', False):
            print_error("Demo mode is not active. Use 'demo start' first.")
            return False
        
        if args.session:
            session = self.demo_manager.get_session(args.session)
            if not session:
                print_error(f"Session {args.session} not found")
                return False
            return self._interact_with_session(session)
        
        # Interactive demo prompt
        print_success("Entering interactive demo mode")
        print_info("Available commands:")
        print_info("  use <module>     - Use a demo module")
        print_info("  sessions         - List active sessions")
        print_info("  sessions -i <id> - Interact with session")
        print_info("  help             - Show this help")
        print_info("  exit             - Exit demo mode")
        
        while True:
            try:
                user_input = input("\n(demo)> ").strip()
                
                if not user_input:
                    continue
                
                parts = user_input.split()
                command = parts[0].lower()
                
                if command == 'exit':
                    break
                elif command == 'help':
                    self._show_demo_help()
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
                        self._manage_sessions(type('Args', (), {'list': True})())
                else:
                    print_error(f"Unknown command: {command}")
            
            except KeyboardInterrupt:
                print_info("\nUse 'exit' to quit demo mode")
            except EOFError:
                break
        
        return True
    
    def _use_demo_module(self, module_name: str) -> bool:
        """Use a demo module"""
        if module_name not in self.demo_modules:
            print_error(f"Demo module '{module_name}' not found")
            print_info("Available modules: " + ", ".join(self.demo_modules.keys()))
            return False
        
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
        
        return True
    
    def _interact_with_session(self, session) -> bool:
        """Interact with a specific session"""
        print_success(f"Interacting with session {session.id}")
        print_info("Type 'exit' to return to demo mode")
        
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
                print_info("\nUse 'exit' to return to demo mode")
            except EOFError:
                break
        
        return True
    
    def _show_demo_help(self):
        """Show demo help"""
        print_info("=== Demo Mode Help ===")
        print_info("Commands:")
        print_info("  use <module>     - Use a demo module")
        print_info("  sessions         - List active sessions")
        print_info("  sessions -i <id> - Interact with session")
        print_info("  help             - Show this help")
        print_info("  exit             - Exit demo mode")
        print_info("")
        print_info("Available modules:")
        for module_name in self.demo_modules.keys():
            print_info(f"  {module_name}")
