#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
import re

class Module(Post):
    """Windows System Enumeration Module"""
    
    __info__ = {
        "name": "Windows Gather System Information",
        "description": "Enumerates Windows system information including OS details, users, processes, services, network configuration, and security settings",
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "session_type": [SessionType.METERPRETER, SessionType.SHELL],
    }
    

    def _get_session_id_value(self) -> str:
        """Return the current session_id option value as a string."""
        value = ""
        try:
            value = getattr(self, 'session_id', '') or ""
        except Exception:
            value = ""
        if hasattr(value, 'value'):
            value = value.value
        return str(value or "").strip()
    
    def _ensure_cache_fields(self):
        """Ensure per-instance cache attributes exist."""
        if not hasattr(self, "_cached_session_id"):
            self._cached_session_id = None
        if not hasattr(self, "_cached_session"):
            self._cached_session = None
        if not hasattr(self, "_session_type_value"):
            self._session_type_value = ""
    
    def _ensure_session_context(self):
        """Load and cache the session metadata."""
        self._ensure_cache_fields()
        session_id_value = self._get_session_id_value()
        if self._cached_session_id == session_id_value and self._cached_session is not None:
            return
        
        self._cached_session_id = session_id_value
        self._cached_session = None
        self._session_type_value = ""
        
        if not session_id_value or not self.framework or not hasattr(self.framework, 'session_manager'):
            return
        
        session = self.framework.session_manager.get_session(session_id_value)
        if session:
            self._cached_session = session
            session_type = getattr(session, 'session_type', '') or ''
            self._session_type_value = session_type.lower()
    
    def _get_session(self):
        """Return the cached session object."""
        self._ensure_session_context()
        return self._cached_session
    
    def _is_meterpreter_session(self) -> bool:
        """Return True if the active session is a meterpreter session."""
        self._ensure_session_context()
        return self._session_type_value == SessionType.METERPRETER.value
    
    def _execute_meterpreter_cmd(self, command: str):
        """Execute a meterpreter-only command if the session supports it."""
        if not command or not self._is_meterpreter_session():
            return ""
        return self._execute_cmd(command)
    
    def _execute_windows_command(self, command: str):
        """
        Execute a standard Windows command across both meterpreter and classic shells.
        Automatically prefixes with 'shell' when running from meterpreter.
        """
        if not command:
            return ""
        cmd = command
        if self._is_meterpreter_session():
            cmd = f"shell {command}"
        return self._execute_cmd(cmd)
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format"""
        if bytes_value is None or bytes_value == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def _fix_encoding(self, text: str) -> str:
        """Fix encoding issues in text output, especially Windows-1252/CP850 to UTF-8"""
        if not text:
            return text
        
        try:
            # If it's bytes, decode it properly
            if isinstance(text, bytes):
                # Try Windows-1252 first (common Windows encoding for cmd.exe)
                try:
                    text = text.decode('windows-1252', errors='replace')
                except:
                    # Try CP850 (another common Windows encoding)
                    try:
                        text = text.decode('cp850', errors='replace')
                    except:
                        # Fallback to UTF-8
                        text = text.decode('utf-8', errors='replace')
            else:
                # If it's already a string but has encoding issues
                # Common patterns:
                # - "Ã©" instead of "é" (UTF-8 decoded as Latin-1)
                # - "é" displayed as something else (Windows-1252/CP850 decoded as UTF-8)
                
                # Check for common mis-encoding patterns
                has_misencoded = False
                
                # Pattern 1: UTF-8 bytes decoded as Latin-1/Windows-1252
                # Examples: "Ã©" (should be "é"), "Ã¨" (should be "è"), "Ã " (should be "à")
                if 'Ã' in text:
                    has_misencoded = True
                    try:
                        # Try to fix: encode as Latin-1 (preserves bytes) then decode as UTF-8
                        text = text.encode('latin1', errors='ignore').decode('utf-8', errors='replace')
                    except:
                        pass
                
                # Pattern 2: Windows-1252/CP850 characters that look wrong
                # If we see characters that are typical of Windows encodings but displayed wrong
                # Try to re-encode and decode properly
                if not has_misencoded:
                    # Check if text contains characters that suggest Windows encoding issues
                    # Common Windows-1252 characters that might be problematic: é, è, à, ç, etc.
                    # If they appear as single bytes that are invalid UTF-8, we need to fix them
                    try:
                        # Try encoding as Windows-1252 then decoding as UTF-8
                        # This handles cases where Windows-1252 text was decoded as something else
                        text_bytes = text.encode('latin1', errors='ignore')
                        # Try Windows-1252 first
                        try:
                            text = text_bytes.decode('windows-1252', errors='replace')
                        except:
                            # Try CP850
                            try:
                                text = text_bytes.decode('cp850', errors='replace')
                            except:
                                # Keep original
                                pass
                    except:
                        pass
                
                # Remove null bytes
                if '\x00' in text:
                    text = text.replace('\x00', '')
                
                # Remove other control characters that might cause issues
                text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
                
        except Exception:
            # If all else fails, just return the text as-is
            pass
        
        return text
    
    def _execute_cmd(self, command: str, description: str = None) -> str:
        """Execute a command and return output"""
        if not command:
            return ""
        try:
            if description:
                print_info(f"[*] {description}")
            output = self.cmd_execute(command)
            if output:
                # Fix encoding issues
                output = self._fix_encoding(output.strip())
            return output if output else ""
        except Exception as e:
            if description:
                print_warning(f"    Failed: {str(e)}")
            return ""
    
    def _gather_system_info(self):
        """Gather basic system information"""
        print_info("=" * 70)
        print_info("System Information")
        print_info("=" * 70)
        
        # Get system info via Meterpreter sysinfo
        print_status("Collecting system information...")
        sysinfo = self._execute_meterpreter_cmd("sysinfo")
        if sysinfo:
            print_info(sysinfo)
        else:
            # Fallback to individual commands
            hostname = self._execute_windows_command("hostname")
            os_info = self._execute_windows_command("ver")
            arch = self._execute_windows_command("wmic os get osarchitecture /value")
            
            if hostname:
                print_info(f"Hostname: {hostname}")
            if os_info:
                print_info(f"OS Version: {os_info}")
            if arch:
                print_info(f"Architecture: {arch}")
        
        print_info("")
    
    def _gather_user_info(self):
        """Gather user and privilege information"""
        print_info("=" * 70)
        print_info("User Information")
        print_info("=" * 70)
        
        # Current user
        print_status("Getting current user...")
        user = self._execute_meterpreter_cmd("getuid")
        if user:
            print_info(f"Current User: {user}")
        else:
            user = self._execute_windows_command("whoami")
            if user:
                print_info(f"Current User: {user}")
        
        # User groups
        print_status("Enumerating user groups...")
        groups = self._execute_windows_command("whoami /groups")
        if groups:
            print_info("User Groups:")
            for line in groups.split('\n')[:10]:  # Show first 10 lines
                if line.strip():
                    print_info(f"  {line}")
        
        # Privileges
        print_status("Enumerating privileges...")
        privs = self._execute_windows_command("whoami /priv")
        if privs:
            print_info("Privileges:")
            for line in privs.split('\n')[:15]:
                if line.strip():
                    print_info(f"  {line}")
        
        print_info("")
    
    def _gather_process_info(self):
        """Gather process information"""
        print_info("=" * 70)
        print_info("Process Information")
        print_info("=" * 70)
        
        # Current process
        print_status("Getting current process ID...")
        pid = self._execute_meterpreter_cmd("getpid")
        if pid:
            print_info(f"Current PID: {pid}")
        else:
            pid = self._execute_windows_command("powershell -NoLogo -NoProfile -Command \"$PID\"")
            if pid:
                print_info(f"Current PID: {pid}")
        
        # List processes
        print_status("Enumerating running processes...")
        processes = self._execute_meterpreter_cmd("ps")
        if processes:
            # Show first 20 lines
            lines = processes.split('\n')[:20]
            for line in lines:
                if line.strip():
                    print_info(f"  {line}")
            if len(processes.split('\n')) > 20:
                print_info(f"  ... ({len(processes.split('\n')) - 20} more processes)")
        else:
            # Fallback
            ps_list = self._execute_windows_command("tasklist /v")
            if ps_list:
                lines = ps_list.split('\n')[:15]
                for line in lines:
                    if line.strip():
                        print_info(f"  {line}")
        
        print_info("")
    
    def _gather_network_info(self):
        """Gather network configuration"""
        print_info("=" * 70)
        print_info("Network Configuration")
        print_info("=" * 70)
        
        # IP configuration
        print_status("Gathering network configuration...")
        ipconfig = self._execute_windows_command("ipconfig /all")
        if ipconfig:
            lines = ipconfig.split('\n')[:30]  # Show first 30 lines
            for line in lines:
                if line.strip():
                    print_info(f"  {line}")
        
        # Active connections
        print_status("Enumerating network connections...")
        netstat = self._execute_windows_command("netstat -ano")
        if netstat:
            lines = netstat.split('\n')[:20]
            for line in lines:
                if line.strip():
                    print_info(f"  {line}")
        
        print_info("")
    
    def _gather_service_info(self):
        """Gather Windows services information"""
        print_info("=" * 70)
        print_info("Windows Services")
        print_info("=" * 70)
        
        # List services
        print_status("Enumerating Windows services...")
        services = self._execute_windows_command("sc query state= all")
        if services:
            lines = services.split('\n')[:40]  # Show first 40 lines
            for line in lines:
                if line.strip():
                    print_info(f"  {line}")
        
        print_info("")
    
    def _gather_security_info(self):
        """Gather security-related information"""
        print_info("=" * 70)
        print_info("Security Information")
        print_info("=" * 70)
        
        # UAC status
        print_status("Checking UAC status...")
        uac = self._execute_windows_command("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA")
        if uac:
            print_info("UAC Configuration:")
            for line in uac.split('\n'):
                if line.strip() and 'EnableLUA' in line:
                    print_info(f"  {line}")
        
        # Password policy
        print_status("Checking password policy...")
        pass_policy = self._execute_windows_command("net accounts")
        if pass_policy:
            print_info("Password Policy:")
            for line in pass_policy.split('\n'):
                if line.strip():
                    print_info(f"  {line}")
        
        # Firewall status
        print_status("Checking firewall status...")
        firewall = self._execute_windows_command("netsh advfirewall show allprofiles state")
        if firewall:
            print_info("Firewall Status:")
            for line in firewall.split('\n'):
                line = line.strip()
                if line:
                    # Fix encoding for firewall output
                    line = self._fix_encoding(line)
                    print_info(f"  {line}")
        
        print_info("")
    
    def _gather_environment_info(self):
        """Gather environment variables"""
        print_info("=" * 70)
        print_info("Environment Variables")
        print_info("=" * 70)
        
        print_status("Gathering environment variables...")
        env = self._execute_windows_command("set")
        if env:
            # Show important environment variables
            important_vars = ['PATH', 'USERNAME', 'USERPROFILE', 'COMPUTERNAME', 
                            'SYSTEMROOT', 'TEMP', 'TMP', 'PROGRAMFILES', 'PROGRAMDATA']
            lines = env.split('\n')
            for line in lines:
                if any(var in line for var in important_vars):
                    print_info(f"  {line}")
        
        print_info("")
    
    def _gather_disk_info(self):
        """Gather disk information"""
        print_info("=" * 70)
        print_info("Disk Information")
        print_info("=" * 70)
        
        # Disk usage - use a better command that gives formatted output
        print_status("Gathering disk information...")
        disk = self._execute_windows_command("wmic logicaldisk get size,freespace,caption,volumename")
        if disk:
            lines = disk.split('\n')
            # Skip header line
            header_found = False
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Skip header
                if 'Caption' in line and 'Size' in line:
                    header_found = True
                    continue
                
                if not header_found:
                    continue
                
                # Parse the line: Caption, FreeSpace, Size, VolumeName
                # Format: C:  510905020416  59336007680  Acer
                parts = re.split(r'\s+', line)
                if len(parts) >= 3:
                    drive = parts[0]
                    try:
                        # Try to parse size and freespace
                        # The order might vary, so we need to identify which is which
                        # Usually: Caption, FreeSpace, Size
                        if len(parts) >= 3:
                            # Find the largest number (size) and second largest (freespace)
                            numbers = []
                            for part in parts[1:]:
                                try:
                                    num = int(part)
                                    numbers.append(num)
                                except ValueError:
                                    continue
                            
                            if len(numbers) >= 2:
                                # Sort to find size (largest) and freespace
                                numbers.sort(reverse=True)
                                size = numbers[0]
                                freespace = numbers[1]
                                
                                used = size - freespace
                                used_percent = (used / size * 100) if size > 0 else 0
                                
                                # Get volume name if available
                                volume_name = parts[-1] if len(parts) > 3 and not parts[-1].isdigit() else ""
                                
                                disk_info = f"  {drive}:"
                                if volume_name:
                                    disk_info += f" ({volume_name})"
                                disk_info += f"\n    Total: {self._format_bytes(size)}"
                                disk_info += f"\n    Free:  {self._format_bytes(freespace)}"
                                disk_info += f"\n    Used:  {self._format_bytes(used)} ({used_percent:.1f}%)"
                                print_info(disk_info)
                            else:
                                # Fallback: just show the line as-is
                                print_info(f"  {line}")
                    except (ValueError, IndexError):
                        # If parsing fails, just show the line
                        print_info(f"  {line}")
        else:
            # Fallback to simpler command
            disk_simple = self._execute_windows_command("wmic logicaldisk get caption,freespace,size")
            if disk_simple:
                for line in disk_simple.split('\n'):
                    if line.strip() and 'Caption' not in line:
                        print_info(f"  {line}")
        
        # Current directory
        print_status("Getting current directory...")
        pwd = self._execute_meterpreter_cmd("pwd")
        if pwd:
            print_info(f"\nCurrent Directory: {pwd}")
        else:
            pwd = self._execute_windows_command("cd")
            if pwd:
                print_info(f"\nCurrent Directory: {pwd}")
        
        print_info("")
    
    def run(self):
        """Run the enumeration module"""
        try:
            session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
            
            print_info("")
            print_success("Starting Windows System Enumeration...")
            print_info("")
            
            # Gather all information
            self._gather_system_info()
            self._gather_user_info()
            self._gather_process_info()
            self._gather_network_info()
            self._gather_service_info()
            self._gather_security_info()
            self._gather_environment_info()
            self._gather_disk_info()
            
            print_info("=" * 70)
            print_success("Windows System Enumeration Complete")
            print_info("=" * 70)
            
            return True
            
        except ProcedureError as e:
            raise e
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Enumeration error: {str(e)}")
