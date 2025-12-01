#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH shell implementation for SSH sessions
"""

import socket
import threading
import time
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error

class SSHShell(BaseShell):
    """SSH shell implementation for SSH sessions"""
    
    def __init__(self, session_id: str, session_type: str = "ssh", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        
        # SSH connection parameters
        self.host = "localhost"
        self.port = 22
        self.username = "user"
        self.password = ""
        self.private_key = None
        self.connection = None
        self.channel = None
        self.is_connected = False
        
        # Try to get SSH connection from session/listener
        self._initialize_ssh_connection()
        
        # Initialize environment (will be populated when connection is established)
        self.environment_vars = {}
        self.current_directory = ""
        
        # Register built-in commands
        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'env': self._cmd_env,
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'pwd': self._cmd_pwd,
            'ls': self._cmd_ls,
            'cd': self._cmd_cd,
            'echo': self._cmd_echo,
            'exit': self._cmd_exit,
            'disconnect': self._cmd_disconnect,
            'reconnect': self._cmd_reconnect,
            'status': self._cmd_status
        }
    
    @property
    def shell_name(self) -> str:
        return "ssh"
    
    @property
    def prompt_template(self) -> str:
        return "{username}@{hostname}:{directory}$ " if not self.is_root else "{username}@{hostname}:{directory}# "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        # If not connected, show clear error indicator
        if not self.is_connected or not self.connection:
            return "[!] Not connected to SSH server > "
        return self.prompt_template.format(
            username=self.username or "user",
            hostname=self.hostname or "localhost",
            directory=self.current_directory or "/"
        )
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the SSH shell"""
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
        
        # Try to initialize connection if not connected
        if not self.is_connected or not self.connection:
            self._initialize_ssh_connection()
        
        # Try to execute via SSH connection
        if self.is_connected and self.connection:
            try:
                return self._execute_remote_command(command)
            except Exception as e:
                # Connection might have been lost, try to reinitialize
                self.is_connected = False
                self.connection = None
                self._initialize_ssh_connection()
                if self.is_connected and self.connection:
                    try:
                        return self._execute_remote_command(command)
                    except Exception as e2:
                        return {'output': '', 'status': 1, 'error': f'SSH execution error: {str(e2)}'}
                return {'output': '', 'status': 1, 'error': f'SSH execution error: {str(e)}'}
        else:
            return {'output': '', 'status': 1, 'error': 'Not connected to SSH server'}
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return list(self.builtin_commands.keys())
    
    def _initialize_ssh_connection(self):
        """Initialize SSH connection from session/listener"""
        try:
            if not self.framework:
                return
            
            # Get session data
            session = self.framework.session_manager.get_session(self.session_id)
            if not session:
                return
            
            # Try to get connection from listener
            # Search in current module first
            if hasattr(self.framework, 'current_module') and self.framework.current_module:
                listener = self.framework.current_module
                if hasattr(listener, '_session_connections') and self.session_id in listener._session_connections:
                    self.connection = listener._session_connections[self.session_id]
                    if self.connection:
                        self._setup_connection_from_session(session)
                        return
            
            # Search in all loaded modules (listeners)
            if hasattr(self.framework, 'modules') and self.framework.modules:
                for module_name, module in self.framework.modules.items():
                    if hasattr(module, '_session_connections') and self.session_id in module._session_connections:
                        self.connection = module._session_connections[self.session_id]
                        if self.connection:
                            self._setup_connection_from_session(session)
                            return
                    # Also try connections dict with host:port
                    if hasattr(module, 'connections'):
                        conn_id = f"{session.host}:{session.port}"
                        if conn_id in module.connections:
                            self.connection = module.connections[conn_id]
                            if self.connection:
                                self._setup_connection_from_session(session)
                                return
            
            # Try to get from connections dict using host:port in current module
            if hasattr(self.framework, 'current_module') and self.framework.current_module:
                listener = self.framework.current_module
                if hasattr(listener, 'connections'):
                    conn_id = f"{session.host}:{session.port}"
                    if conn_id in listener.connections:
                        self.connection = listener.connections[conn_id]
                        if self.connection:
                            self._setup_connection_from_session(session)
                            return
            
            # Search in session data for listener reference
            if session.data:
                # Try to find listener by listener_id stored in session data
                listener_id = session.data.get('listener_id')
                if listener_id and hasattr(self.framework, 'active_listeners'):
                    listener = self.framework.active_listeners.get(listener_id)
                    if listener:
                        # Check _session_connections first
                        if hasattr(listener, '_session_connections') and self.session_id in listener._session_connections:
                            self.connection = listener._session_connections[self.session_id]
                            if self.connection:
                                self._setup_connection_from_session(session)
                                return
                        # Also check connections dict
                        if hasattr(listener, 'connections'):
                            conn_id = f"{session.host}:{session.port}"
                            if conn_id in listener.connections:
                                self.connection = listener.connections[conn_id]
                                if self.connection:
                                    self._setup_connection_from_session(session)
                                    return
                
                # Check if session data contains listener_type or connection info
                listener_type = session.data.get('listener_type', '')
                if listener_type:
                    # Try to find listener by type in modules
                    if hasattr(self.framework, 'modules') and self.framework.modules:
                        for module_name, module in self.framework.modules.items():
                            if hasattr(module, 'TYPE_MODULE') and module.TYPE_MODULE == 'listener':
                                if hasattr(module, '_session_connections') and self.session_id in module._session_connections:
                                    self.connection = module._session_connections[self.session_id]
                                    if self.connection:
                                        self._setup_connection_from_session(session)
                                        return
                                # Also check connections dict
                                if hasattr(module, 'connections'):
                                    conn_id = f"{session.host}:{session.port}"
                                    if conn_id in module.connections:
                                        self.connection = module.connections[conn_id]
                                        if self.connection:
                                            self._setup_connection_from_session(session)
                                            return
                
        except Exception as e:
            print_error(f"Error initializing SSH connection: {str(e)}")
    
    def _setup_connection_from_session(self, session):
        """Setup connection parameters from session data"""
        self.is_connected = True
        self.host = session.host
        self.port = session.port
        self.hostname = session.host
        
        # Extract username from session data if available
        if session.data:
            if 'username' in session.data:
                self.username = session.data['username']
            elif 'address' in session.data and isinstance(session.data['address'], tuple):
                # Try to get from address if available
                pass
        
        # Update environment
        self.environment_vars['SSH_CLIENT'] = f"{self.host} {self.port} 22"
        self.environment_vars['SSH_CONNECTION'] = f"{self.host} {self.port} {self.host} 22"
        self.environment_vars['USER'] = self.username
        self.environment_vars['HOME'] = f"/home/{self.username}"
        self.current_directory = f"/home/{self.username}"
        self.environment_vars['PWD'] = self.current_directory
        
        print_info(f"SSH connection initialized from session {self.session_id}")
    
    def connect(self, host: str, port: int = 22, username: str = "user", password: str = "", private_key: str = None) -> bool:
        """Connect to SSH server"""
        try:
            import paramiko
            
            self.host = host
            self.port = port
            self.username = username
            self.password = password
            self.private_key = private_key
            
            # Create SSH connection using paramiko
            self.connection = paramiko.SSHClient()
            self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.connection.connect(host, port, username, password)
            
            self.is_connected = True
            self.hostname = host
            self.environment_vars['SSH_CLIENT'] = f"{host} {port} 22"
            self.environment_vars['SSH_CONNECTION'] = f"{host} {port} {host} 22"
            self.environment_vars['USER'] = username
            self.environment_vars['HOME'] = f"/home/{username}"
            self.current_directory = f"/home/{username}"
            self.environment_vars['PWD'] = self.current_directory
            
            return True
        except Exception as e:
            print_error(f"SSH connection failed: {str(e)}")
            return False
    
    def disconnect(self):
        """Disconnect from SSH server"""
        self.is_connected = False
        self.connection = None
        self.channel = None
    
    def _execute_remote_command(self, command: str) -> Dict[str, Any]:
        """Execute command on remote SSH server using paramiko"""
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'SSH connection not available'}
        
        try:
            import paramiko
            
            # Execute command via SSH
            stdin, stdout, stderr = self.connection.exec_command(command)
            
            # Read output
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            # Get exit status
            exit_status = stdout.channel.recv_exit_status()
            
            # Update current directory if command was 'cd'
            if command.strip().startswith('cd '):
                # Execute pwd to get new directory
                stdin_pwd, stdout_pwd, _ = self.connection.exec_command('pwd')
                new_dir = stdout_pwd.read().decode('utf-8', errors='ignore').strip()
                if new_dir:
                    self.current_directory = new_dir
                    self.environment_vars['PWD'] = new_dir
            
            return {
                'output': output,
                'status': exit_status,
                'error': error
            }
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'SSH execution error: {str(e)}'}
    
    # Built-in command implementations
    def _cmd_help(self, args: str) -> Dict[str, Any]:
        """Show help"""
        help_text = """SSH Shell Commands:
  help                    Show this help
  clear                   Clear screen
  history [n]             Show command history
  env                     Show environment variables
  whoami                  Print current user
  id                      Print user and group IDs
  pwd                     Print working directory
  ls [dir]                List directory contents
  cd [dir]                Change directory
  echo [text]             Echo text
  exit                    Exit shell
  disconnect              Disconnect from SSH
  reconnect               Reconnect to SSH
  status                  Show connection status

SSH Connection:
  Use connect() method to establish SSH connection
  Commands are executed on the remote server"""
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
    
    def _cmd_whoami(self, args: str) -> Dict[str, Any]:
        """Print current user"""
        if not self.is_connected or not self.connection:
            return {'output': '', 'status': 1, 'error': 'Not connected to SSH server. Cannot execute command.'}
        result = self._execute_remote_command("whoami")
        if result['output']:
            self.username = result['output'].strip()
        return result
    
    def _cmd_id(self, args: str) -> Dict[str, Any]:
        """Print user and group IDs"""
        if not self.is_connected or not self.connection:
            return {'output': '', 'status': 1, 'error': 'Not connected to SSH server. Cannot execute command.'}
        return self._execute_remote_command("id")
    
    def _cmd_pwd(self, args: str) -> Dict[str, Any]:
        """Print working directory"""
        if not self.is_connected or not self.connection:
            return {'output': '', 'status': 1, 'error': 'Not connected to SSH server. Cannot execute command.'}
        return self._execute_remote_command("pwd")
    
    def _cmd_ls(self, args: str) -> Dict[str, Any]:
        """List directory contents"""
        if not self.is_connected or not self.connection:
            return {'output': '', 'status': 1, 'error': 'Not connected to SSH server. Cannot execute command.'}
        command = f"ls {args}" if args else "ls"
        return self._execute_remote_command(command)
    
    def _cmd_cd(self, args: str) -> Dict[str, Any]:
        """Change directory"""
        if not self.is_connected or not self.connection:
            return {'output': '', 'status': 1, 'error': 'Not connected to SSH server. Cannot execute command.'}
        if not args:
            target_dir = self.environment_vars.get('HOME', f'/home/{self.username}')
        else:
            target_dir = args
        result = self._execute_remote_command(f"cd {target_dir} && pwd")
        if result['status'] == 0 and result['output']:
            self.current_directory = result['output'].strip()
            self.environment_vars['PWD'] = self.current_directory
        return result
    
    def _cmd_echo(self, args: str) -> Dict[str, Any]:
        """Echo text"""
        return {'output': f'{args}\n', 'status': 0, 'error': ''}
    
    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        """Exit shell"""
        self.disconnect()
        self.deactivate()
        return {'output': 'exit\n', 'status': 0, 'error': ''}
    
    def _cmd_disconnect(self, args: str) -> Dict[str, Any]:
        """Disconnect from SSH"""
        self.disconnect()
        return {'output': 'Disconnected from SSH server\n', 'status': 0, 'error': ''}
    
    def _cmd_reconnect(self, args: str) -> Dict[str, Any]:
        """Reconnect to SSH"""
        if self.host and self.port:
            success = self.connect(self.host, self.port, self.username, self.password, self.private_key)
            if success:
                return {'output': f'Reconnected to {self.host}:{self.port}\n', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'Failed to reconnect'}
        else:
            return {'output': '', 'status': 1, 'error': 'No previous connection to reconnect to'}
    
    def _cmd_status(self, args: str) -> Dict[str, Any]:
        """Show connection status"""
        status = "Connected" if self.is_connected else "Disconnected"
        connection_info = f"SSH Status: {status}\n"
        if self.is_connected:
            connection_info += f"Host: {self.host}:{self.port}\n"
            connection_info += f"User: {self.username}\n"
            connection_info += f"Directory: {self.current_directory}\n"
        
        return {'output': connection_info, 'status': 0, 'error': ''}
