#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shell manager for handling different shell types
"""

from typing import Dict, Any, List, Optional, Type
from .base_shell import BaseShell
from .classic_shell import ClassicShell
from .javascript_shell import JavaScriptShell
from .ssh_shell import SSHShell
from .meterpreter_shell import MeterpreterShell
from .php_shell import PHPShell
from .mysql_shell import MySQLShell
from .ftp_shell import FTPShell
from .aws_sqs_shell import AWSSQSShell
from .aws_sqs_command_shell import AWSSQSCommandShell
from core.output_handler import print_info, print_error, print_success

class ShellManager:
    """Manager for different shell types"""
    
    def __init__(self):
        self.shells: Dict[str, BaseShell] = {}
        self.shell_types: Dict[str, Type[BaseShell]] = {
            'classic': ClassicShell,
            'javascript': JavaScriptShell,
            'ssh': SSHShell,
            'meterpreter': MeterpreterShell,
            'php': PHPShell,
            'mysql': MySQLShell,
            'ftp': FTPShell,
            'aws_sqs': AWSSQSShell,
            'aws_sqs_command': AWSSQSCommandShell
        }
        self.active_shell: Optional[str] = None
    
    def create_shell(self, session_id: str, shell_type: str, session_type: str = "unknown", browser_server=None, **kwargs) -> Optional[BaseShell]:
        """
        Create a new shell instance
        
        Args:
            session_id: Unique session identifier
            shell_type: Type of shell to create
            session_type: Type of session
            **kwargs: Additional arguments for shell creation
            
        Returns:
            BaseShell instance or None if creation failed
        """
        try:
            if shell_type not in self.shell_types:
                print_error(f"Unknown shell type: {shell_type}")
                print_info(f"Available shell types: {', '.join(self.shell_types.keys())}")
                return None
            
            # Create shell instance
            shell_class = self.shell_types[shell_type]
            if shell_type == "javascript" and browser_server:
                shell = shell_class(session_id, session_type, browser_server)
            elif shell_type in ("ssh", "php", "mysql", "ftp", "aws_sqs", "aws_sqs_command"):
                # These shells need framework to get connection from listener
                framework = kwargs.get('framework')
                shell = shell_class(session_id, session_type, framework)
            else:
                shell = shell_class(session_id, session_type)
            
            # Apply additional configuration
            if 'username' in kwargs:
                shell.username = kwargs['username']
            if 'hostname' in kwargs:
                shell.hostname = kwargs['hostname']
            if 'is_root' in kwargs:
                shell.is_root = kwargs['is_root']
            if 'current_directory' in kwargs:
                shell.current_directory = kwargs['current_directory']
            
            # Store shell
            self.shells[session_id] = shell
            
            print_success(f"Created {shell_type} shell for session {session_id}")
            return shell
            
        except Exception as e:
            print_error(f"Failed to create shell: {str(e)}")
            return None
    
    def get_shell(self, session_id: str) -> Optional[BaseShell]:
        """Get shell by session ID"""
        return self.shells.get(session_id)
    
    def remove_shell(self, session_id: str) -> bool:
        """Remove shell by session ID"""
        if session_id in self.shells:
            shell = self.shells.pop(session_id)
            shell.deactivate()
            
            # Clear active shell if it was this one
            if self.active_shell == session_id:
                self.active_shell = None
            
            print_success(f"Removed shell for session {session_id}")
            return True
        return False
    
    def set_active_shell(self, session_id: str) -> bool:
        """Set active shell"""
        if session_id in self.shells:
            self.active_shell = session_id
            return True
        return False
    
    def get_active_shell(self) -> Optional[BaseShell]:
        """Get active shell"""
        if self.active_shell and self.active_shell in self.shells:
            return self.shells[self.active_shell]
        return None
    
    def execute_command(self, session_id: str, command: str, framework=None) -> Dict[str, Any]:
        """Execute command in specific shell"""
        shell = self.get_shell(session_id)
        
        # If no shell exists, try to create one automatically
        if not shell:
            # Try to auto-create shell based on session type
            if framework and hasattr(framework, 'session_manager'):
                session = framework.session_manager.get_session(session_id)
                if session:
                    # Determine shell type from session type
                    session_type = session.session_type.lower()
                    if session_type == 'ssh':
                        shell_type = 'ssh'
                    elif session_type == 'meterpreter':
                        shell_type = 'meterpreter'
                    elif session_type in ('php', 'http', 'https'):
                        shell_type = 'php'
                    elif session_type == 'mysql':
                        shell_type = 'mysql'
                    elif session_type == 'ftp':
                        shell_type = 'ftp'
                    elif session_type == 'aws' or session_type == 'aws_sqs':
                        # Check if it's a command executor or interactive shell
                        if session_data and session_data.get('command_executor'):
                            shell_type = 'aws_sqs_command'
                        else:
                            shell_type = 'aws_sqs'
                    else:
                        shell_type = 'classic'
                    
                    # Try to create shell automatically
                    shell = self.create_shell(
                        session_id=session_id,
                        shell_type=shell_type,
                        session_type=session_type,
                        framework=framework
                    )
        
        if not shell:
            return {'output': '', 'status': 1, 'error': f'No shell found for session {session_id} and could not create one automatically'}
        
        if not shell.is_active:
            # Try to activate the shell
            shell.activate()
        
        try:
            return shell.execute_command(command)
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Command execution error: {str(e)}'}
    
    def execute_active_command(self, command: str) -> Dict[str, Any]:
        """Execute command in active shell"""
        if not self.active_shell:
            return {'output': '', 'status': 1, 'error': 'No active shell'}
        
        return self.execute_command(self.active_shell, command)
    
    def get_shell_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get shell information"""
        shell = self.get_shell(session_id)
        if shell:
            return shell.get_shell_info()
        return None
    
    def list_shells(self) -> List[Dict[str, Any]]:
        """List all shells"""
        shells_info = []
        for session_id, shell in self.shells.items():
            info = shell.get_shell_info()
            info['is_active'] = (session_id == self.active_shell)
            shells_info.append(info)
        return shells_info
    
    def get_available_shell_types(self) -> List[str]:
        """Get available shell types"""
        return list(self.shell_types.keys())
    
    def get_shell_type_info(self, shell_type: str) -> Optional[Dict[str, Any]]:
        """Get information about a shell type"""
        if shell_type not in self.shell_types:
            return None
        
        shell_class = self.shell_types[shell_type]
        return {
            'name': shell_class.__name__,
            'shell_name': shell_class().shell_name if hasattr(shell_class(), 'shell_name') else shell_type,
            'description': shell_class.__doc__ or f"{shell_type} shell implementation",
            'available_commands': len(shell_class().get_available_commands()) if hasattr(shell_class(), 'get_available_commands') else 0
        }
    
    def switch_shell(self, session_id: str) -> bool:
        """Switch to a different shell"""
        if session_id in self.shells:
            self.active_shell = session_id
            print_success(f"Switched to shell for session {session_id}")
            return True
        else:
            print_error(f"Shell for session {session_id} not found")
            return False
    
    def get_shell_prompt(self, session_id: str) -> str:
        """Get shell prompt for session"""
        shell = self.get_shell(session_id)
        if shell:
            return shell.get_prompt()
        return "> "
    
    def get_active_shell_prompt(self) -> str:
        """Get active shell prompt"""
        shell = self.get_active_shell()
        if shell:
            return shell.get_prompt()
        return "> "
    
    def cleanup_inactive_shells(self):
        """Clean up inactive shells"""
        inactive_sessions = []
        for session_id, shell in self.shells.items():
            if not shell.is_active:
                inactive_sessions.append(session_id)
        
        for session_id in inactive_sessions:
            self.remove_shell(session_id)
        
        if inactive_sessions:
            print_info(f"Cleaned up {len(inactive_sessions)} inactive shells")
    
    def get_shell_statistics(self) -> Dict[str, Any]:
        """Get shell statistics"""
        total_shells = len(self.shells)
        active_shells = sum(1 for shell in self.shells.values() if shell.is_active)
        
        shell_type_counts = {}
        for shell in self.shells.values():
            shell_type = shell.shell_name
            shell_type_counts[shell_type] = shell_type_counts.get(shell_type, 0) + 1
        
        return {
            'total_shells': total_shells,
            'active_shells': active_shells,
            'inactive_shells': total_shells - active_shells,
            'shell_type_counts': shell_type_counts,
            'active_shell_id': self.active_shell
        }
