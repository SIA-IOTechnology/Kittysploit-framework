#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Classic shell implementation for standard sessions
"""

import os
import subprocess
import shlex
import socket
import select
import time
import re
import ntpath
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error

class ClassicShell(BaseShell):
    """Classic shell implementation for standard sessions"""
    
    def __init__(self, session_id: str, session_type: str = "standard", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection: Optional[socket.socket] = None
        self.is_windows = False
        self.platform_detected = False
        self._windows_cwd_strategy: Optional[str] = None
        
        # Initialize environment (will be updated based on detected OS)
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
            'dir': self._cmd_dir,  # Windows equivalent of ls
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
        
        # Initialize connection from framework
        self._initialize_connection()
    
    @property
    def shell_name(self) -> str:
        return "classic"
    
    @property
    def prompt_template(self) -> str:
        """Get prompt template based on detected OS"""
        if self.is_windows:
            return "PS {directory}> "
        else:
            return "{username}@{hostname}:{directory}$ " if not self.is_root else "{username}@{hostname}:{directory}# "
    
    def get_prompt(self) -> str:
        """Get the current shell prompt"""
        if self.is_windows:
            dir_display = self._normalize_windows_path_for_prompt(self.current_directory)
            return self.prompt_template.format(directory=dir_display)
        else:
            # Remove any trailing > or >> for Unix as well
            dir_display = self.current_directory.rstrip('>').rstrip()
            return self.prompt_template.format(
                username=self.username,
                hostname=self.hostname,
                directory=dir_display
            )
    
    def _get_windows_drive(self) -> str:
        """Return current drive (default C:)."""
        m = re.match(r'^\s*([A-Za-z]:)\\', str(self.current_directory or ""))
        return (m.group(1) if m else "C:")

    def _strip_powershell_prompt_prefix(self, s: str) -> str:
        """Remove leading 'PS ' repetitions."""
        if not s:
            return s
        out = s.strip()
        # Remove repeated "PS " prefixes (e.g. "PS PS C:\...>")
        while re.match(r'^\s*PS\s+', out, flags=re.IGNORECASE):
            out = re.sub(r'^\s*PS\s+', '', out, flags=re.IGNORECASE).lstrip()
        return out

    def _normalize_windows_path(self, raw: str) -> str:
        """
        Normalize Windows path strings coming from remote output:
        - strips 'PS ' prefixes and trailing prompt markers (> / >>)
        - removes PowerShell provider prefixes
        - ensures a drive letter (defaults to current drive)
        """
        if raw is None:
            return ""

        s = self._strip_powershell_prompt_prefix(str(raw))

        # Remove trailing prompt markers: ">", ">>"
        s = re.sub(r'\s*>{1,2}\s*$', '', s).strip()

        # Remove provider prefix like: Microsoft.PowerShell.Core\FileSystem::C:\Users\...
        if "::" in s:
            s = s.split("::", 1)[1].strip()

        # Handle "Path : C:\..." formats
        m_path = re.match(r'(?i)^\s*path\s*:?\s*(.+)$', s)
        if m_path:
            s = m_path.group(1).strip()

        # Convert forward slashes to backslashes for normalization
        s = s.replace("/", "\\")

        # Ensure drive letter
        if re.match(r'^[A-Za-z]:\\', s):
            return ntpath.normpath(s)
        if s.startswith("\\"):
            return ntpath.normpath(self._get_windows_drive() + s)

        # If it's relative, join with current directory
        base = str(self.current_directory or (self._get_windows_drive() + "\\"))
        base = self._strip_powershell_prompt_prefix(base)
        base = re.sub(r'\s*>{1,2}\s*$', '', base).replace("/", "\\")
        if not re.match(r'^[A-Za-z]:\\', base):
            base = self._get_windows_drive() + "\\" + base.lstrip("\\")

        return ntpath.normpath(ntpath.join(base, s))

    def _normalize_windows_path_for_prompt(self, raw: str) -> str:
        """Normalize and ensure we never end up with 'PS PS ...' in prompt. Use C:\\Users\\user when raw is Unix-style."""
        if not raw or (str(raw).startswith('/') and ':\\' not in str(raw)):
            return self._get_windows_drive() + "\\Users\\user"
        path = self._normalize_windows_path(raw)
        if not path or (path.startswith('/') and ':\\' not in path):
            return self._get_windows_drive() + "\\Users\\user"
        return path

    def _set_current_directory(self, raw: str):
        """Set current directory with proper normalization."""
        if self.is_windows:
            self.current_directory = self._normalize_windows_path(raw)
        else:
            self.current_directory = str(raw).strip()

    def _extract_windows_path_from_cd_result(self, raw: str) -> Optional[str]:
        """From 'cd' command output (may contain C:\\path>cd or C:\\path>), extract the path only."""
        if not raw or raw.strip().startswith('cd:'):
            return None
        for line in raw.split('\n'):
            line = line.strip()
            # CMD prompt line: "C:\path>" or "C:\path>command"
            m = re.match(r'^([A-Za-z]:\\[^>]*)\s*>', line)
            if m:
                return m.group(1).strip().rstrip('\\') or m.group(1).strip()
            # Plain path line: "C:\path"
            if re.match(r'^[A-Za-z]:\\', line) and '>' not in line:
                return line.rstrip('\\')
        return None

    def _clean_path(self, raw: str) -> str:
        """Normalize raw path output coming from remote shells."""
        if not raw:
            return ""

        if self.is_windows:
            # Reject lines that look like CMD/PowerShell error messages (e.g. ".Path était inattendu")
            error_terms = [
                "cannot find path", "error", "denied", "not found",
                "inattendu", "unexpected", "is not recognized", "n'est pas reconnu",
                "était", "was unexpected", ".path", "path tait",
            ]
            lines = [line.strip() for line in str(raw).splitlines() if line.strip()]
            candidates: List[str] = []
            for line in lines:
                lower = line.lower()
                if lower in {"path", "location", "current location"}:
                    continue
                if lower.startswith("path :"):
                    line = line.split(":", 1)[1].strip()
                    lower = line.lower()
                if re.match(r"^-+$", line):
                    continue
                if any(term in lower for term in error_terms):
                    continue
                # Must look like a Windows path (e.g. C:\ or D:\)
                if not re.match(r"^[A-Za-z]:\\", line):
                    continue
                candidates.append(line)

            for line in reversed(candidates):
                normalized = self._normalize_windows_path(line)
                if normalized:
                    return normalized
            return ""

        lines = [line.strip() for line in str(raw).splitlines() if line.strip()]
        if not lines:
            return ""
        return os.path.normpath(lines[-1])

    def _fetch_remote_cwd(self, timeout: float = 2.0) -> Optional[str]:
        """Try multiple commands to retrieve the remote current directory."""
        if not self.connection:
            return None

        commands: List[str]
        if self.is_windows:
            # Try "cd" first: works in CMD and PowerShell; our Zig/CMD payload only has cmd.exe
            base_cmds = [
                'cd',
                '(Get-Location -ErrorAction SilentlyContinue).Path',
                '(Get-Location).Path',
                'Get-Location | Select-Object -ExpandProperty Path',
                'Get-Location',
                'pwd',
            ]
            preferred = [self._windows_cwd_strategy] if self._windows_cwd_strategy else []
            commands = [cmd for cmd in preferred if cmd] + [cmd for cmd in base_cmds if cmd not in preferred]
        else:
            commands = ['pwd']

        for cmd in commands:
            result = self._send_command_raw(cmd, timeout=timeout)
            if not result:
                continue
            cleaned = self._clean_path(result)
            if cleaned:
                if self.is_windows:
                    self._windows_cwd_strategy = cmd
                return cleaned

        if self.is_windows:
            self._windows_cwd_strategy = None
        return None
    
    def _initialize_connection(self):
        """Initialize connection from framework/listener"""
        if not self.framework:
            return
        
        try:
            # Get session from framework
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session:
                    # Try to get connection from listener
                    listener_id = session.data.get('listener_id') if hasattr(session, 'data') else None
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener:
                            # Check _session_connections first
                            if hasattr(listener, '_session_connections') and self.session_id in listener._session_connections:
                                self.connection = listener._session_connections[self.session_id]
                            # Also check connections dict
                            elif hasattr(listener, 'connections'):
                                conn_id = f"{session.host}:{session.port}"
                                if conn_id in listener.connections:
                                    self.connection = listener.connections[conn_id]
                    
                    # If still no connection, try to get from session data
                    if not self.connection and hasattr(session, 'data'):
                        # Connection might be stored directly in session data
                        # (though it's usually filtered out for serialization)
                        pass
                    
                    # Use platform from session (set by listener from payload) to avoid sending detection commands
                    if self.connection and hasattr(session, 'data') and session.data.get('platform'):
                        pl = session.data['platform']
                        if isinstance(pl, str) and pl.lower() == 'windows':
                            self.is_windows = True
                            self.platform_detected = True
                            self._set_current_directory("C:\\Users\\user")
                            self.environment_vars = {
                                'PATH': 'C:\\Windows\\System32;C:\\Windows',
                                'USERPROFILE': self.current_directory.replace('/', '\\'),
                                'USERNAME': 'user',
                                'PWD': self.current_directory.replace('/', '\\'),
                                'COMSPEC': 'C:\\Windows\\System32\\cmd.exe'
                            }
                            self.hostname = "localhost"
                            # Fetch actual remote cwd so prompt shows correct path
                            remote_cwd = self._fetch_remote_cwd()
                            if remote_cwd:
                                self._set_current_directory(remote_cwd)
                        elif isinstance(pl, str) and pl.lower() == 'linux':
                            self.is_windows = False
                            self.platform_detected = True
                            self.hostname = "localhost"
                    # Detect platform only if not already set (sends cd / echo %OS% etc.)
                    if self.connection and not self.platform_detected:
                        self._detect_platform()
        except Exception as e:
            print_error(f"Error initializing connection: {e}")
    
    def _detect_platform(self):
        """Detect the remote operating system"""
        if self.platform_detected or not self.connection:
            return
        
        try:
            # Try multiple detection methods for Windows
            # Method 1: Try 'cd' command on Windows (returns current directory)
            result = self._send_command_raw('cd', timeout=2)
            
            if result:
                result_clean = result.strip()
                # Check for Windows path indicators (C:\, D:\, etc.)
                if ':\\' in result_clean or (len(result_clean) > 1 and result_clean[1] == ':'):
                    self.is_windows = True
                    self.platform_detected = True
                    # Extract path only: result may be "C:\path>cd" or "C:\path>" or banner+path; take first C:\... line
                    path_for_cd = self._extract_windows_path_from_cd_result(result_clean)
                    if path_for_cd:
                        self._set_current_directory(path_for_cd)
                    else:
                        self._set_current_directory("C:\\Users\\user")
                    
                    # Update environment for Windows
                    self.environment_vars = {
                        'PATH': 'C:\\Windows\\System32;C:\\Windows',
                        'USERPROFILE': self.current_directory.replace('/', '\\'),
                        'USERNAME': 'user',
                        'PWD': self.current_directory.replace('/', '\\'),
                        'COMSPEC': 'C:\\Windows\\System32\\cmd.exe'
                    }
                    self.hostname = "localhost"
                    return
            
            # Method 2: Try PowerShell-specific command
            result = self._send_command_raw('$PSVersionTable.PSVersion', timeout=2)
            if result and ('Major' in result or 'Version' in result or result.strip().isdigit()):
                self.is_windows = True
                self.platform_detected = True
                # Get current directory
                pwd_result = self._send_command_raw('pwd', timeout=2)
                if pwd_result:
                    # PowerShell pwd might return full path
                    path = pwd_result.strip()
                    if path.startswith('Path'):
                        # Parse "Path : C:\Users\..."
                        parts = path.split(':', 1)
                        if len(parts) > 1:
                            path = parts[1].strip()
                    self._set_current_directory(path)
                else:
                    self._set_current_directory("C:\\Users\\user")
                
                self.environment_vars = {
                    'PATH': 'C:\\Windows\\System32;C:\\Windows',
                    'USERPROFILE': self.current_directory.replace('/', '\\'),
                    'USERNAME': 'user',
                    'PWD': self.current_directory.replace('/', '\\'),
                    'COMSPEC': 'C:\\Windows\\System32\\cmd.exe'
                }
                self.hostname = "localhost"
                return
            
            # Method 3: Try echo %OS% (CMD)
            result = self._send_command_raw('echo %OS%', timeout=2)
            if result:
                result_lower = result.lower().strip()
                if 'windows' in result_lower or 'nt' in result_lower:
                    self.is_windows = True
                    self.platform_detected = True
                    # Get current directory
                    cd_result = self._send_command_raw('cd', timeout=2)
                    path_for_cd = self._extract_windows_path_from_cd_result(cd_result.strip()) if cd_result else None
                    if path_for_cd:
                        self._set_current_directory(path_for_cd)
                    else:
                        self._set_current_directory("C:\\Users\\user")
                    
                    self.environment_vars = {
                        'PATH': 'C:\\Windows\\System32;C:\\Windows',
                        'USERPROFILE': self.current_directory.replace('/', '\\'),
                        'USERNAME': 'user',
                        'PWD': self.current_directory.replace('/', '\\'),
                        'COMSPEC': 'C:\\Windows\\System32\\cmd.exe'
                    }
                    self.hostname = "localhost"
                    return
            
            # If none of the Windows detection methods worked, assume Unix-like
            self.is_windows = False
            self.platform_detected = True
        except Exception as e:
            # If detection fails, default to Unix
            self.is_windows = False
            self.platform_detected = True
    
    def _send_command_raw(self, command: str, timeout: float = 5.0) -> Optional[str]:
        """Send a raw command via socket and receive response"""
        if not self.connection:
            return None
        
        try:
            # Send command with newline
            cmd_bytes = (command + '\r\n').encode('utf-8', errors='ignore')
            self.connection.sendall(cmd_bytes)
            
            # Receive response with timeout
            self.connection.settimeout(timeout)
            response = b''
            start_time = time.time()
            max_wait = timeout
            
            while time.time() - start_time < max_wait:
                try:
                    data = self.connection.recv(4096)
                    if not data:
                        break
                    response += data
                    # Wait a bit more to see if more data is coming
                    time.sleep(0.2)
                    # Try to receive more if available (non-blocking check)
                    self.connection.settimeout(0.2)
                    try:
                        more_data = self.connection.recv(4096)
                        if more_data:
                            response += more_data
                        else:
                            # No more data, we're done
                            break
                    except socket.timeout:
                        # No more data available
                        break
                except socket.timeout:
                    # If we have some data, return it
                    if response:
                        break
                    continue
            
            # Decode response
            if response:
                decoded = response.decode('utf-8', errors='ignore')
                # Remove command echo / PowerShell prompts if present
                lines = decoded.split('\n')
                filtered_lines = []
                current_path_windows = None
                if self.is_windows:
                    current_path_windows = self._normalize_windows_path_for_prompt(self.current_directory).rstrip("\\").lower()
                
                for line in lines:
                    line_stripped = line.strip()
                    # Skip empty lines
                    if not line_stripped:
                        continue
                    line_lower = line_stripped.lower()
                    # Skip Windows CMD banner lines (so they never appear in command output)
                    if any(banner in line_lower for banner in [
                        'microsoft windows [version',
                        '(c) microsoft corporation',
                        'tous droits', 'all rights reserved', 'tous droits rservs'
                    ]):
                        continue
                    # Skip CMD-style prompt lines: "C:\path>" or "C:\path>command" (keep for 'cd' so we can extract path)
                    if command.strip() != 'cd' and re.match(r'^[A-Za-z]:\\.*\s*>', line_stripped):
                        continue
                    # Skip command echo
                    if line_stripped == command.strip():
                        continue
                    # Skip PowerShell prompt patterns (PS C:\path> / PS C:\path>> / repeated PS)
                    if self.is_windows and re.match(r'^\s*(?:PS\s+)+([A-Z]:\\.*)\s*>{1,2}\s*$', line_stripped, re.IGNORECASE):
                        continue
                    # Also skip prompt-like patterns missing drive (rare): "PS \Users\...>"
                    if self.is_windows and re.match(r'^\s*(?:PS\s+)+\\.*\s*>{1,2}\s*$', line_stripped, re.IGNORECASE):
                        continue
                    # Skip lines that are just the current path (PowerShell sometimes echoes it)
                    if self.is_windows and current_path_windows:
                        path_candidate = self._normalize_windows_path(line_stripped).rstrip("\\").lower()
                        if path_candidate == current_path_windows:
                            continue
                    filtered_lines.append(line)
                
                result = '\n'.join(filtered_lines).strip()
                return result if result else None
            return None
        except (ConnectionResetError, BrokenPipeError) as e:
            print_error(f"Connection closed by target: {e}")
            self.connection = None
            return None
        except OSError as e:
            if getattr(e, 'winerror', None) == 10054 or getattr(e, 'errno', None) == 10054:
                print_error("Connection closed by target (WinError 10054). The payload process may have exited.")
                self.connection = None
                return None
            print_error(f"Error sending command: {e}")
            return None
        except Exception as e:
            print_error(f"Error sending command: {e}")
            return None
    
    def _filter_output(self, output: str) -> str:
        """Filter output to remove unwanted lines like 'Répertoire' or 'Directory'"""
        if not output:
            return output
        
        lines = output.split('\n')
        filtered_lines = []
        import re
        
        # Get current directory path for comparison (normalize both formats)
        current_path_windows = self.current_directory.replace('/', '\\') if self.is_windows else None
        current_path_unix = self.current_directory
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            line_lower = line_stripped.lower()
            
            # Skip lines containing directory labels in various languages
            if any(keyword in line_lower for keyword in [
                'répertoire', 'repertoire', 'directory', 'rép', 'rép.',
            ]):
                # This is a directory label line, skip it completely
                continue
            
            # Skip Windows dir header lines
            if self.is_windows:
                # Skip header line with "Mode", "LastWriteTime", "Length", "Name"
                if all(header in line_lower for header in ['mode', 'lastwritetime', 'length', 'name']):
                    continue
                # Skip separator line (dashes)
                if re.match(r'^[\s\-]+$', line_stripped):
                    continue
                # Skip lines that are just "Répertoire de ..." or similar
                if re.match(r'^\s*(r[ée]pertoire|directory)\s+(de|of|:)\s*', line_lower):
                    continue
                
                # Skip lines that are just the current path (PowerShell sometimes echoes it)
                # Check if line is exactly the current path (with or without trailing backslash)
                path_normalized = line_stripped.replace('/', '\\').rstrip('\\')
                if current_path_windows and path_normalized.lower() == current_path_windows.lower().rstrip('\\'):
                    # This is just the path being echoed, skip it
                    continue
                
                # Also check for PowerShell prompt-like patterns (PS C:\path>)
                if re.match(r'^\s*PS\s+[A-Z]:\\.*>?\s*$', line_stripped, re.IGNORECASE):
                    continue
            else:
                # For Unix, skip only the "total" line
                if line_lower.startswith('total '):
                    continue
                
                # Skip lines that are just the current path
                if current_path_unix and line_stripped == current_path_unix:
                    continue
            
            # Keep all other lines
            filtered_lines.append(line)
        
        # Additional check: if the last line is just the path, remove it
        if filtered_lines and self.is_windows:
            last_line = filtered_lines[-1].strip()
            if current_path_windows and last_line.replace('/', '\\').lower() == current_path_windows.lower().rstrip('\\'):
                filtered_lines.pop()
        
        return '\n'.join(filtered_lines)
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a command in the shell"""
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        
        # Add to history
        self.add_to_history(command)
        
        # If we have a connection, use it to execute commands remotely
        if self.connection:
            # Detect platform on first command if not already detected
            if not self.platform_detected:
                self._detect_platform()
            
            # Parse command
            try:
                parts = shlex.split(command) if not self.is_windows else command.split()
                cmd = parts[0] if parts else command
                args = parts[1:] if len(parts) > 1 else []
            except ValueError:
                # Fallback for Windows-style commands
                parts = command.split()
                cmd = parts[0] if parts else command
                args = parts[1:] if len(parts) > 1 else []
            
            # Handle built-in commands that need special processing
            if cmd.lower() in ['cd', 'pwd', 'whoami']:
                # These might need special handling, but try remote first
                result = self._send_command_raw(command, timeout=5.0)
                if result is not None:
                    if cmd.lower() == 'cd':
                        # If cd succeeded, update local current_directory deterministically (no remote pwd needed)
                        # Filter result to remove path echo
                        filtered_result = self._filter_output(result)
                        # Don't show output for successful cd (standard behavior)
                        if 'error' not in filtered_result.lower() and 'not found' not in filtered_result.lower() and 'cannot' not in filtered_result.lower():
                            # Update directory locally based on argument (if any)
                            if self.is_windows:
                                target = args[0] if args else self.current_directory
                                # Special cases: cd with no args keeps directory (or goes home)
                                if not args:
                                    # keep current; users can type 'cd ~' if they want
                                    pass
                                else:
                                    new_dir = self._normalize_windows_path(target)
                                    self._set_current_directory(new_dir)
                            else:
                                # Unix-like: compute locally if possible
                                if args:
                                    target = args[0]
                                    if not target.startswith('/'):
                                        target = os.path.join(self.current_directory, target)
                                    self.current_directory = os.path.normpath(target)
                            return {'output': '', 'status': 0, 'error': ''}
                        else:
                            return {'output': '', 'status': 1, 'error': filtered_result if filtered_result else 'cd: No such file or directory'}
                    elif cmd.lower() == 'pwd':
                        if self.is_windows:
                            remote_path = self._fetch_remote_cwd()
                            if remote_path:
                                self._set_current_directory(remote_path)
                            return {'output': self._normalize_windows_path_for_prompt(self.current_directory) + '\n', 'status': 0, 'error': ''}
                        if result:
                            cleaned = self._clean_path(result)
                            if cleaned:
                                self.current_directory = cleaned
                                return {'output': cleaned + '\n', 'status': 0, 'error': ''}
                            self.current_directory = result.strip()
                            return {'output': result.strip() + '\n', 'status': 0, 'error': ''}
                    
                    return {'output': result + '\n' if result else '', 'status': 0, 'error': ''}
                else:
                    # Fallback to built-in if remote fails
                    if cmd in self.builtin_commands:
                        return self.builtin_commands[cmd](args)
            
            # For other commands, send directly to remote
            result = self._send_command_raw(command, timeout=10.0)
            if result is not None:
                # Filter output to remove unwanted lines
                filtered_result = self._filter_output(result)
                # Update current directory if command was cd (fallback for commands not caught above)
                if cmd.lower() == 'cd':
                    import time
                    time.sleep(0.3)
                    new_dir = self._fetch_remote_cwd()
                    if new_dir:
                        self._set_current_directory(new_dir)
                return {'output': filtered_result + '\n' if filtered_result else '', 'status': 0, 'error': ''}
            else:
                return {'output': '', 'status': 1, 'error': 'Connection lost or no response'}
        
        # Fallback: execute locally if no connection (for testing/development)
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
        
        # Try to execute as external command (local fallback)
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
        # If we have a connection, use remote execution
        if self.connection:
            if not args:
                target_dir = self.environment_vars.get('HOME', '/home/user') if not self.is_windows else 'C:\\Users\\user'
            else:
                target_dir = args[0]
            
            cmd = f'cd {target_dir}'
            result = self._send_command_raw(cmd, timeout=2.0)
            
            # Try to get new directory (this is what we'll display in the prompt)
            new_path = self._fetch_remote_cwd()
            if new_path:
                self._set_current_directory(new_path)
            
            # Filter result to remove unwanted text
            if result:
                filtered_result = self._filter_output(result)
                # If cd succeeded, don't show output (standard behavior)
                if 'error' not in filtered_result.lower() and 'not found' not in filtered_result.lower() and 'cannot' not in filtered_result.lower():
                    return {'output': '', 'status': 0, 'error': ''}
                else:
                    return {'output': '', 'status': 1, 'error': filtered_result if filtered_result else f'cd: {target_dir}: No such file or directory'}
            else:
                # If no error message, assume success
                return {'output': '', 'status': 0, 'error': ''}
        
        # Fallback to local
        if not args:
            target_dir = self.environment_vars.get('HOME', '/home/user') if not self.is_windows else 'C:\\Users\\user'
        else:
            target_dir = args[0]
        
        # Handle relative paths
        if self.is_windows:
            if ':' not in target_dir and not target_dir.startswith('\\'):
                target_dir = os.path.join(self.current_directory, target_dir)
        else:
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
        # If we have a connection, get actual directory from remote
        if self.connection:
            remote_path = self._fetch_remote_cwd()
            if remote_path:
                self._set_current_directory(remote_path)
                if self.is_windows:
                    prompt_path = self._normalize_windows_path_for_prompt(self.current_directory)
                else:
                    prompt_path = self.current_directory
                return {'output': prompt_path + '\n', 'status': 0, 'error': ''}
        
        return {'output': self.current_directory + '\n', 'status': 0, 'error': ''}
    
    def _cmd_ls(self, args: List[str]) -> Dict[str, Any]:
        """List directory contents (Unix)"""
        if self.is_windows:
            # Redirect to dir command on Windows
            return self._cmd_dir(args)
        
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
    
    def _cmd_dir(self, args: List[str]) -> Dict[str, Any]:
        """List directory contents (Windows)"""
        # If we have a connection, use remote execution
        if self.connection:
            cmd = 'dir' + (' ' + ' '.join(args) if args else '')
            result = self._send_command_raw(cmd, timeout=5.0)
            if result is not None:
                # Filter output to remove "Répertoire" and headers
                filtered_result = self._filter_output(result)
                return {'output': filtered_result + '\n' if filtered_result else '', 'status': 0, 'error': ''}
        
        # Fallback to local (for testing)
        try:
            if not args:
                target_dir = self.current_directory
            else:
                target_dir = args[0]
            
            if not os.path.exists(target_dir):
                return {'output': '', 'status': 1, 'error': f'dir: {target_dir}: No such file or directory'}
            
            if not os.path.isdir(target_dir):
                return {'output': target_dir + '\n', 'status': 0, 'error': ''}
            
            # List directory contents
            items = os.listdir(target_dir)
            items.sort()
            
            # Format output (Windows style)
            output_lines = []
            for item in items:
                item_path = os.path.join(target_dir, item)
                if os.path.isdir(item_path):
                    output_lines.append(f"<DIR>  {item}")
                else:
                    output_lines.append(f"       {item}")
            
            return {'output': '\n'.join(output_lines) + '\n', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': f'dir error: {str(e)}'}
    
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
