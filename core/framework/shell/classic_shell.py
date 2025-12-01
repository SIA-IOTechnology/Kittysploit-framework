#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Classic shell implementation for standard sessions
"""

import os
import subprocess
import shlex
from typing import Dict, Any, List
from .base_shell import BaseShell
from core.output_handler import print_info, print_error

class ClassicShell(BaseShell):
    """Classic shell implementation for standard sessions"""
    
    def __init__(self, session_id: str, session_type: str = "standard"):
        super().__init__(session_id, session_type)
        
        # Initialize environment
        self.environment_vars = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': '/home/user',
            'USER': 'user',
            'PWD': '/home/user',
            'SHELL': '/bin/bash'
        }
        self.current_directory = "/home/user"
        
        # Register built-in commands
        self.builtin_commands = {
            'cd': self._cmd_cd,
            'pwd': self._cmd_pwd,
            'ls': self._cmd_ls,
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'echo': self._cmd_echo,
            'env': self._cmd_env,
            'export': self._cmd_export,
            'unset': self._cmd_unset,
            'history': self._cmd_history,
            'clear': self._cmd_clear,
            'help': self._cmd_help,
            'exit': self._cmd_exit
        }
    
    @property
    def shell_name(self) -> str:
        return "classic"
    
    @property
    def prompt_template(self) -> str:
        return "{username}@{hostname}:{directory}$ " if not self.is_root else "{username}@{hostname}:{directory}# "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.prompt_template.format(
            username=self.username,
            hostname=self.hostname,
            directory=self.current_directory
        )
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the shell"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        # Add to history
        self.add_to_history(command)
        
        # Parse command
        try:
            parts = shlex.split(command)
            cmd = parts[0]
            args = parts[1:] if len(parts) > 1 else []
        except ValueError as e:
            return {'output': '', 'status': 1, 'error': f'Parse error: {str(e)}'}
        
        # Check for built-in commands
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': f'Built-in command error: {str(e)}'}
        
        # Try to execute as external command
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=self.current_directory,
                env={**os.environ, **self.environment_vars},
                timeout=30
            )
            return {
                'output': result.stdout,
                'status': result.returncode,
                'error': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'output': '', 'status': 1, 'error': 'Command timed out'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Execution error: {str(e)}'}
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return list(self.builtin_commands.keys())
    
    # Built-in command implementations
    def _cmd_cd(self, args: List[str]) -> Dict[str, Any]:
        """Change directory"""
        if not args:
            target_dir = self.environment_vars.get('HOME', '/home/user')
        else:
            target_dir = args[0]
        
        # Handle relative paths
        if not target_dir.startswith('/'):
            target_dir = os.path.join(self.current_directory, target_dir)
        
        # Normalize path
        target_dir = os.path.normpath(target_dir)
        
        if os.path.exists(target_dir) and os.path.isdir(target_dir):
            self.current_directory = target_dir
            self.environment_vars['PWD'] = target_dir
            return {'output': '', 'status': 0, 'error': ''}
        else:
            return {'output': '', 'status': 1, 'error': f'cd: {target_dir}: No such file or directory'}
    
    def _cmd_pwd(self, args: List[str]) -> Dict[str, Any]:
        """Print working directory"""
        return {'output': self.current_directory + '\n', 'status': 0, 'error': ''}
    
    def _cmd_ls(self, args: List[str]) -> Dict[str, Any]:
        """List directory contents"""
        try:
            if not args:
                target_dir = self.current_directory
            else:
                target_dir = args[0]
                if not target_dir.startswith('/'):
                    target_dir = os.path.join(self.current_directory, target_dir)
            
            if not os.path.exists(target_dir):
                return {'output': '', 'status': 1, 'error': f'ls: {target_dir}: No such file or directory'}
            
            if not os.path.isdir(target_dir):
                return {'output': target_dir + '\n', 'status': 0, 'error': ''}
            
            # List directory contents
            items = os.listdir(target_dir)
            items.sort()
            
            # Format output
            output_lines = []
            for item in items:
                item_path = os.path.join(target_dir, item)
                if os.path.isdir(item_path):
                    output_lines.append(f"{item}/")
                elif os.path.isfile(item_path):
                    output_lines.append(item)
                else:
                    output_lines.append(f"{item}*")
            
            return {'output': '\n'.join(output_lines) + '\n', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'ls error: {str(e)}'}
    
    def _cmd_whoami(self, args: List[str]) -> Dict[str, Any]:
        """Print current user"""
        return {'output': self.username + '\n', 'status': 0, 'error': ''}
    
    def _cmd_id(self, args: List[str]) -> Dict[str, Any]:
        """Print user and group IDs"""
        uid = 0 if self.is_root else 1000
        gid = 0 if self.is_root else 1000
        groups = "0" if self.is_root else "1000"
        return {'output': f'uid={uid}({self.username}) gid={gid}({self.username}) groups={groups}({self.username})\n', 'status': 0, 'error': ''}
    
    def _cmd_echo(self, args: List[str]) -> Dict[str, Any]:
        """Echo arguments"""
        output = ' '.join(args) if args else ''
        return {'output': output + '\n', 'status': 0, 'error': ''}
    
    def _cmd_env(self, args: List[str]) -> Dict[str, Any]:
        """Print environment variables"""
        env_output = []
        for key, value in self.environment_vars.items():
            env_output.append(f"{key}={value}")
        return {'output': '\n'.join(env_output) + '\n', 'status': 0, 'error': ''}
    
    def _cmd_export(self, args: List[str]) -> Dict[str, Any]:
        """Set environment variable"""
        if not args:
            return {'output': '', 'status': 0, 'error': ''}
        
        for arg in args:
            if '=' in arg:
                key, value = arg.split('=', 1)
                self.environment_vars[key] = value
            else:
                # Export existing variable
                if arg in os.environ:
                    self.environment_vars[arg] = os.environ[arg]
        
        return {'output': '', 'status': 0, 'error': ''}
    
    def _cmd_unset(self, args: List[str]) -> Dict[str, Any]:
        """Unset environment variable"""
        for arg in args:
            self.environment_vars.pop(arg, None)
        return {'output': '', 'status': 0, 'error': ''}
    
    def _cmd_history(self, args: List[str]) -> Dict[str, Any]:
        """Show command history"""
        limit = 50
        if args and args[0].isdigit():
            limit = int(args[0])
        
        history = self.get_history(limit)
        output_lines = []
        for i, cmd in enumerate(history, 1):
            output_lines.append(f"{i:4d}  {cmd}")
        
        return {'output': '\n'.join(output_lines) + '\n', 'status': 0, 'error': ''}
    
    def _cmd_clear(self, args: List[str]) -> Dict[str, Any]:
        """Clear screen"""
        return {'output': '\033[2J\033[H', 'status': 0, 'error': ''}
    
    def _cmd_help(self, args: List[str]) -> Dict[str, Any]:
        """Show help"""
        help_text = """Available commands:
  cd [dir]        Change directory
  pwd             Print working directory
  ls [dir]        List directory contents
  whoami          Print current user
  id              Print user and group IDs
  echo [text]     Echo text
  env             Print environment variables
  export [var=val] Set environment variable
  unset [var]     Unset environment variable
  history [n]     Show command history
  clear           Clear screen
  help            Show this help
  exit            Exit shell"""
        return {'output': help_text + '\n', 'status': 0, 'error': ''}
    
    def _cmd_exit(self, args: List[str]) -> Dict[str, Any]:
        """Exit shell"""
        self.deactivate()
        return {'output': 'exit\n', 'status': 0, 'error': ''}
