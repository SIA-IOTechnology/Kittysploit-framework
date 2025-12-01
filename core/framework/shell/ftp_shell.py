#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FTP shell implementation for FTP sessions
"""

import os
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class FTPShell(BaseShell):
    """FTP shell implementation for FTP sessions"""
    
    def __init__(self, session_id: str, session_type: str = "ftp", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.ftp_client = None
        self.host = "localhost"
        self.port = 21
        self.username = "anonymous"
        
        # Initialize FTP environment
        self.environment_vars = {
            'FTP_HOST': 'localhost',
            'FTP_USER': 'anonymous'
        }
        
        # Register built-in commands
        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'pwd': self._cmd_pwd,
            'cd': self._cmd_cd,
            'ls': self._cmd_ls,
            'dir': self._cmd_ls,
            'get': self._cmd_get,
            'put': self._cmd_put,
            'download': self._cmd_get,
            'upload': self._cmd_put,
            'mkdir': self._cmd_mkdir,
            'rmdir': self._cmd_rmdir,
            'delete': self._cmd_delete,
            'rm': self._cmd_delete,
            'rename': self._cmd_rename,
            'mv': self._cmd_rename,
            'size': self._cmd_size,
            'binary': self._cmd_binary,
            'ascii': self._cmd_ascii,
            'passive': self._cmd_passive,
            'active': self._cmd_active,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit
        }
        
        # Initialize FTP connection
        self._initialize_ftp_connection()
    
    def _initialize_ftp_connection(self):
        """Initialize FTP connection from session/listener"""
        try:
            if not self.framework:
                return
            
            # Get session data
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session:
                    # Extract connection info from session data
                    if session.data:
                        self.host = session.data.get('host', 'localhost')
                        self.port = session.data.get('port', 21)
                        self.username = session.data.get('username', 'anonymous')
                    
                    # Try to get FTP connection from listener
                    listener_id = session.data.get('listener_id') if session.data else None
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            connection = listener._session_connections.get(self.session_id)
                            if connection:
                                # Check if it's an FTP connection
                                from ftplib import FTP
                                if isinstance(connection, FTP):
                                    self.ftp_client = connection
                                    try:
                                        self.current_directory = connection.pwd()
                                    except:
                                        self.current_directory = "/"
                                    return
                    
                    # If connection found in additional_data
                    if session.data and 'connection' in session.data:
                        conn = session.data['connection']
                        from ftplib import FTP
                        if isinstance(conn, FTP):
                            self.ftp_client = conn
                            # Get current directory
                            try:
                                self.current_directory = conn.pwd()
                            except:
                                self.current_directory = "/"
                            return
                    
                    # Try to create FTP client connection
                    try:
                        from ftplib import FTP
                        ftp = FTP()
                        ftp.connect(self.host, self.port)
                        if session.data:
                            password = session.data.get('password', '')
                            ftp.login(self.username, password)
                        self.ftp_client = ftp
                        try:
                            self.current_directory = ftp.pwd()
                        except:
                            self.current_directory = "/"
                    except:
                        pass
                    
        except Exception as e:
            print_warning(f"Could not initialize FTP connection: {e}")
    
    @property
    def shell_name(self) -> str:
        return "ftp"
    
    @property
    def prompt_template(self) -> str:
        return f"ftp [{self.current_directory}]> "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        return self.prompt_template
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the FTP shell"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        # Add to history
        self.add_to_history(command)
        
        # Parse command
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        # Check for built-in commands
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': f'Built-in command error: {str(e)}'}
        
        # Unknown command
        return {'output': '', 'status': 1, 'error': f'Unknown command: {cmd}. Type "help" for available commands.'}
    
    def _cmd_help(self, args: str) -> Dict[str, Any]:
        """Show help"""
        help_text = """
FTP Shell Commands:
==================

Navigation:
  pwd                     - Show current directory
  cd <directory>          - Change directory
  ls, dir                 - List files in current directory
  
File Transfer:
  get <remote> [local]    - Download file from server
  put <local> [remote]    - Upload file to server
  download <remote>       - Alias for get
  upload <local>          - Alias for put
  
File Management:
  mkdir <directory>       - Create directory
  rmdir <directory>       - Remove directory
  delete <file>           - Delete file
  rm <file>               - Alias for delete
  rename <old> <new>      - Rename file
  mv <old> <new>          - Alias for rename
  size <file>             - Show file size
  
Transfer Mode:
  binary                  - Set binary transfer mode
  ascii                   - Set ASCII transfer mode
  passive                 - Set passive mode
  active                  - Set active mode
  
Utility Commands:
  help                    - Show this help
  clear                   - Clear screen
  history                 - Show command history
  exit, quit, disconnect  - Exit FTP shell

Examples:
  cd /var/www/html
  ls
  get index.php
  put backdoor.php
  mkdir uploads
"""
        return {'output': help_text, 'status': 0, 'error': ''}
    
    def _cmd_pwd(self, args: str) -> Dict[str, Any]:
        """Print working directory"""
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                pwd = self.ftp_client.pwd()
                self.current_directory = pwd
                return {'output': pwd, 'status': 0, 'error': ''}
            else:
                # FTP handler from server
                return {'output': self.current_directory, 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_cd(self, args: str) -> Dict[str, Any]:
        """Change directory"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: cd <directory>'}
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.cwd(args)
                self.current_directory = self.ftp_client.pwd()
                return {'output': f'Changed directory to {self.current_directory}', 'status': 0, 'error': ''}
            else:
                # FTP handler from server - simulate cd
                self.current_directory = args
                return {'output': f'Changed directory to {args}', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_ls(self, args: str) -> Dict[str, Any]:
        """List files"""
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                path = args if args else '.'
                files = []
                self.ftp_client.retrlines(f'LIST {path}', files.append)
                return {'output': '\n'.join(files), 'status': 0, 'error': ''}
            else:
                # FTP handler from server
                return {'output': 'Directory listing not available from server handler', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_get(self, args: str) -> Dict[str, Any]:
        """Download file"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: get <remote_file> [local_file]'}
        
        parts = args.split(None, 1)
        remote_file = parts[0]
        local_file = parts[1] if len(parts) > 1 else os.path.basename(remote_file)
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                with open(local_file, 'wb') as f:
                    self.ftp_client.retrbinary(f'RETR {remote_file}', f.write)
                return {'output': f'Downloaded {remote_file} to {local_file}', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'File download not available from server handler'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_put(self, args: str) -> Dict[str, Any]:
        """Upload file"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: put <local_file> [remote_file]'}
        
        parts = args.split(None, 1)
        local_file = parts[0]
        remote_file = parts[1] if len(parts) > 1 else os.path.basename(local_file)
        
        if not os.path.exists(local_file):
            return {'output': '', 'status': 1, 'error': f'Local file not found: {local_file}'}
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                with open(local_file, 'rb') as f:
                    self.ftp_client.storbinary(f'STOR {remote_file}', f)
                return {'output': f'Uploaded {local_file} to {remote_file}', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'File upload not available from server handler'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_mkdir(self, args: str) -> Dict[str, Any]:
        """Create directory"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: mkdir <directory>'}
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.mkd(args)
                return {'output': f'Created directory {args}', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'Directory creation not available from server handler'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_rmdir(self, args: str) -> Dict[str, Any]:
        """Remove directory"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: rmdir <directory>'}
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.rmd(args)
                return {'output': f'Removed directory {args}', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'Directory removal not available from server handler'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_delete(self, args: str) -> Dict[str, Any]:
        """Delete file"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: delete <file>'}
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.delete(args)
                return {'output': f'Deleted {args}', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'File deletion not available from server handler'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_rename(self, args: str) -> Dict[str, Any]:
        """Rename file"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: rename <old> <new>'}
        
        parts = args.split(None, 1)
        if len(parts) < 2:
            return {'output': '', 'status': 1, 'error': 'Usage: rename <old> <new>'}
        
        old_name, new_name = parts[0], parts[1]
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.rename(old_name, new_name)
                return {'output': f'Renamed {old_name} to {new_name}', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'File rename not available from server handler'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_size(self, args: str) -> Dict[str, Any]:
        """Get file size"""
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: size <file>'}
        
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                size = self.ftp_client.size(args)
                return {'output': f'{args}: {size} bytes', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'File size not available from server handler'}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_binary(self, args: str) -> Dict[str, Any]:
        """Set binary mode"""
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.voidcmd('TYPE I')
                return {'output': 'Binary mode set', 'status': 0, 'error': ''}
            else:
                return {'output': 'Binary mode set', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_ascii(self, args: str) -> Dict[str, Any]:
        """Set ASCII mode"""
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.voidcmd('TYPE A')
                return {'output': 'ASCII mode set', 'status': 0, 'error': ''}
            else:
                return {'output': 'ASCII mode set', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_passive(self, args: str) -> Dict[str, Any]:
        """Set passive mode"""
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.set_pasv(True)
                return {'output': 'Passive mode set', 'status': 0, 'error': ''}
            else:
                return {'output': 'Passive mode set', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_active(self, args: str) -> Dict[str, Any]:
        """Set active mode"""
        if not self.ftp_client:
            return {'output': '', 'status': 1, 'error': 'FTP connection not available'}
        
        try:
            from ftplib import FTP
            if isinstance(self.ftp_client, FTP):
                self.ftp_client.set_pasv(False)
                return {'output': 'Active mode set', 'status': 0, 'error': ''}
            else:
                return {'output': 'Active mode set', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'Error: {str(e)}'}
    
    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        """Clear screen"""
        import os
        os.system('clear' if os.name != 'nt' else 'cls')
        return {'output': '', 'status': 0, 'error': ''}
    
    def _cmd_history(self, args: str) -> Dict[str, Any]:
        """Show command history"""
        history = self.get_history()
        if not history:
            return {'output': 'No commands in history', 'status': 0, 'error': ''}
        return {'output': '\n'.join(f"{i+1:4d}  {cmd}" for i, cmd in enumerate(history)), 'status': 0, 'error': ''}
    
    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        """Exit FTP shell"""
        if self.ftp_client:
            try:
                from ftplib import FTP
                if isinstance(self.ftp_client, FTP):
                    self.ftp_client.quit()
            except:
                pass
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}
    
    def get_available_commands(self) -> List[str]:
        """Get list of available commands"""
        return list(self.builtin_commands.keys())

