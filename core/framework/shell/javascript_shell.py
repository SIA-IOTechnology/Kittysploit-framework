#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JavaScript shell implementation for browser sessions
"""

import json
import time
from typing import Dict, Any, List
from .base_shell import BaseShell
from core.output_handler import print_info, print_error

class JavaScriptShell(BaseShell):
    """JavaScript shell implementation for browser sessions"""
    
    def __init__(self, session_id: str, session_type: str = "browser", browser_server=None):
        super().__init__(session_id, session_type)
        self.browser_server = browser_server
        
        # Initialize JavaScript environment
        self.environment_vars = {
            'navigator': 'Mozilla/5.0 (compatible)',
            'location': 'http://localhost',
            'userAgent': 'Mozilla/5.0 (compatible)',
            'platform': 'unknown'
        }
        
        # JavaScript context for local variables only
        self.js_context = {}
        
        # Register built-in commands
        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'env': self._cmd_env,
            'eval': self._cmd_eval,
            'exec': self._cmd_exec,
            'inject': self._cmd_inject,
            'dom': self._cmd_dom,
            'cookies': self._cmd_cookies,
            'localStorage': self._cmd_localStorage,
            'sessionStorage': self._cmd_sessionStorage,
            'navigator': self._cmd_navigator,
            'location': self._cmd_location,
            'exit': self._cmd_exit
        }
    
    @property
    def shell_name(self) -> str:
        return "javascript"
    
    @property
    def prompt_template(self) -> str:
        return "js> "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.prompt_template
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the JavaScript shell"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        # Add to history
        self.add_to_history(command)
        
        # Parse command
        parts = command.strip().split(None, 1)
        cmd = parts[0]
        args = parts[1] if len(parts) > 1 else ""
        
        # Check for built-in commands
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': f'Built-in command error: {str(e)}'}
        
        # Try to execute as JavaScript code
        try:
            return self._execute_javascript(command)
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'JavaScript error: {str(e)}'}
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return list(self.builtin_commands.keys())
    
    def _execute_javascript(self, code: str) -> Dict[str, Any]:
        """Execute JavaScript code in the real browser"""
        code = code.strip()
        
        # Check if browser server is available
        if not self.browser_server:
            return {'output': '', 'status': 1, 'error': 'Browser server not available. Cannot execute JavaScript commands.'}
        
        # Send command to the real browser
        return self._send_to_browser(code)
    
    def _send_to_browser(self, code: str) -> Dict[str, Any]:
        """Send JavaScript code to the real browser"""
        try:
            # Check if session exists in browser server
            if not self.browser_server.get_session(self.session_id):
                return {'output': '', 'status': 1, 'error': f'Session {self.session_id} not found in browser server'}
            
            # Create command to execute JavaScript
            command = {
                "type": "execute_js",
                "code": code
            }
            
            # Send command to the target session
            self.browser_server.send_command_to_session(self.session_id, command)
            
            return {'output': f'[SENT] {code}\n', 'status': 0, 'error': ''}
            
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error sending to browser: {str(e)}'}
    
    
    
    # Built-in command implementations
    def _cmd_help(self, args: str) -> Dict[str, Any]:
        """Show help"""
        help_text = """JavaScript Shell Commands:
  help                    Show this help
  clear                   Clear screen
  history [n]             Show command history
  env                     Show environment variables
  eval <code>             Evaluate JavaScript code
  exec <code>             Execute JavaScript code
  inject <code>           Inject JavaScript into page
  dom                     Show DOM information
  cookies                 Show cookies
  localStorage            Show localStorage
  sessionStorage          Show sessionStorage
  navigator               Show navigator info
  location                Show location info
  exit                    Exit shell

JavaScript Examples:
  console.log("Hello")    Log message
  alert("Alert!")         Show alert
  document.title          Get page title
  window.location.href    Get current URL
  var x = 5               Declare variable
  x + 3                   Evaluate expression"""
        return {'output': help_text + '\n', 'status': 0, 'error': ''}
    
    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        """Clear screen"""
        return {'output': '\033[2J\033[H', 'status': 0, 'error': ''}
    
    def _cmd_history(self, args: str) -> Dict[str, Any]:
        """Show command history"""
        limit = 50
        if args and args.isdigit():
            limit = int(args)
        
        history = self.get_history(limit)
        output_lines = []
        for i, cmd in enumerate(history, 1):
            output_lines.append(f"{i:4d}  {cmd}")
        
        return {'output': '\n'.join(output_lines) + '\n', 'status': 0, 'error': ''}
    
    def _cmd_env(self, args: str) -> Dict[str, Any]:
        """Show environment variables"""
        env_output = []
        for key, value in self.environment_vars.items():
            env_output.append(f"{key}={value}")
        return {'output': '\n'.join(env_output) + '\n', 'status': 0, 'error': ''}
    
    def _cmd_eval(self, args: str) -> Dict[str, Any]:
        """Evaluate JavaScript code"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'eval: code required'}
        
        return self._execute_javascript(args)
    
    def _cmd_exec(self, args: str) -> Dict[str, Any]:
        """Execute JavaScript code"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'exec: code required'}
        
        return self._execute_javascript(args)
    
    def _cmd_inject(self, args: str) -> Dict[str, Any]:
        """Inject JavaScript into page"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'inject: code required'}
        
        # Simulate injection
        return {'output': f'[INJECTED] {args}\n', 'status': 0, 'error': ''}
    
    def _cmd_dom(self, args: str) -> Dict[str, Any]:
        """Show DOM information"""
        dom_info = """DOM Information:
  document.title: "KittySploit Browser Test Page"
  document.URL: "http://localhost:9000/test"
  document.cookie: ""
  document.readyState: "complete"
  document.documentElement: <html>
  document.body: <body>"""
        return {'output': dom_info + '\n', 'status': 0, 'error': ''}
    
    def _cmd_cookies(self, args: str) -> Dict[str, Any]:
        """Show cookies"""
        return {'output': 'No cookies found\n', 'status': 0, 'error': ''}
    
    def _cmd_localStorage(self, args: str) -> Dict[str, Any]:
        """Show localStorage"""
        return {'output': 'localStorage is empty\n', 'status': 0, 'error': ''}
    
    def _cmd_sessionStorage(self, args: str) -> Dict[str, Any]:
        """Show sessionStorage"""
        return {'output': 'sessionStorage is empty\n', 'status': 0, 'error': ''}
    
    def _cmd_navigator(self, args: str) -> Dict[str, Any]:
        """Show navigator info"""
        nav_info = """Navigator Information:
  userAgent: "Mozilla/5.0 (compatible)"
  platform: "unknown"
  language: "en-US"
  cookieEnabled: true
  onLine: true"""
        return {'output': nav_info + '\n', 'status': 0, 'error': ''}
    
    def _cmd_location(self, args: str) -> Dict[str, Any]:
        """Show location info"""
        loc_info = """Location Information:
  href: "http://localhost:9000/test"
  protocol: "http:"
  host: "localhost:9000"
  hostname: "localhost"
  port: "9000"
  pathname: "/test"
  search: ""
  hash: """""
        return {'output': loc_info + '\n', 'status': 0, 'error': ''}
    
    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        """Exit shell"""
        self.deactivate()
        return {'output': 'exit\n', 'status': 0, 'error': ''}
