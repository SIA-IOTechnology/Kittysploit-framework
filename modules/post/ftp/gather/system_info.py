#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ftp.ftp_client import FTPClientMixin
import socket
import re

class Module(Post, FTPClientMixin):
    """FTP System Information Gathering Module"""
    
    __info__ = {
        "name": "FTP Gather System Information",
        "description": "Gathers detailed system information from FTP server including version, features, and capabilities",
        "author": "KittySploit Team",
        "session_type": SessionType.FTP,
    }
    
    def check(self):
        """Check if the module can run"""
        session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
        if not session_id_value:
            print_error("Session ID not set")
            return False
        
        if not self.framework or not hasattr(self.framework, 'session_manager'):
            print_error("Framework or session manager not available")
            return False
        
        session = self.framework.session_manager.get_session(session_id_value)
        if not session:
            print_error(f"Session {session_id_value} not found")
            return False
        
        # Try to get FTP connection to verify it works
        try:
            self.open_ftp()
            return True
        except Exception as e:
            print_error(f"FTP connection error: {e}")
            return False
    
    def _get_banner(self, connection=None, host: str = None, port: int = None) -> str:
        """Get FTP server banner"""
        # Try to get banner from existing connection first
        if connection:
            try:
                # Get welcome message from FTP connection
                welcome = connection.getwelcome()
                if welcome:
                    return welcome.strip()
            except:
                pass
        
        # Fallback: try to connect if host is provided
        if host and host != 'unknown':
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port or 21))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                return banner
            except Exception as e:
                return f"Error: {e}"
        
        return "Banner unavailable (no connection info)"
    
    def _sendcmd_with_timeout(self, connection, cmd, timeout=5):
        """Send FTP command with timeout"""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Command {cmd} timed out")
        
        # Set socket timeout if possible
        if hasattr(connection, 'sock') and connection.sock:
            old_timeout = connection.sock.gettimeout()
            connection.sock.settimeout(timeout)
            try:
                result = connection.sendcmd(cmd)
                return result
            finally:
                connection.sock.settimeout(old_timeout)
        else:
            # Fallback: use signal (Unix only, Windows will use socket timeout)
            try:
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout)
                result = connection.sendcmd(cmd)
                signal.alarm(0)
                return result
            except (TimeoutError, OSError):
                signal.alarm(0)
                raise TimeoutError(f"Command {cmd} timed out")
    
    def _get_system_info(self) -> dict:
        """Get system information from FTP connection"""
        info = {}
        connection = self.open_ftp()
        
        # Set socket timeout on connection
        if hasattr(connection, 'sock') and connection.sock:
            connection.sock.settimeout(5)
        
        # System type
        print_status("  Getting system type...")
        try:
            syst_response = connection.sendcmd('SYST')
            info['system'] = syst_response
        except Exception as e:
            info['system'] = f"Unknown ({str(e)[:50]})"
        
        # Server features
        print_status("  Getting server features...")
        try:
            feat_response = connection.sendcmd('FEAT')
            features = []
            for line in feat_response.split('\n'):
                line = line.strip()
                if line and not line.startswith('211-') and not line.startswith('211 '):
                    features.append(line)
            info['features'] = features
        except Exception as e:
            info['features'] = []
            info['features_error'] = str(e)[:50]
        
        # Current directory
        print_status("  Getting current directory...")
        try:
            info['current_directory'] = connection.pwd()
        except Exception as e:
            info['current_directory'] = f"Unknown ({str(e)[:50]})"
        
        # Check supported commands (with timeout)
        print_status("  Testing supported commands...")
        supported_commands = []
        test_commands = ['MLSD', 'MLST', 'SIZE', 'MDTM', 'REST']
        
        for cmd in test_commands:
            try:
                if hasattr(connection, 'sock') and connection.sock:
                    old_timeout = connection.sock.gettimeout()
                    connection.sock.settimeout(3)
                    try:
                        connection.sendcmd(f'{cmd}')
                        supported_commands.append(cmd)
                    finally:
                        connection.sock.settimeout(old_timeout)
            except:
                pass
        
        info['supported_commands'] = supported_commands
        
        # Check passive mode support (with timeout)
        print_status("  Testing passive mode support...")
        try:
            if hasattr(connection, 'sock') and connection.sock:
                old_timeout = connection.sock.gettimeout()
                connection.sock.settimeout(3)
                try:
                    pasv_response = connection.sendcmd('PASV')
                    info['pasv_support'] = True
                    info['pasv_response'] = pasv_response[:100]  # Limit response length
                finally:
                    connection.sock.settimeout(old_timeout)
            else:
                info['pasv_support'] = False
        except Exception as e:
            info['pasv_support'] = False
        
        # Check extended passive mode (with timeout)
        try:
            if hasattr(connection, 'sock') and connection.sock:
                old_timeout = connection.sock.gettimeout()
                connection.sock.settimeout(3)
                try:
                    epsv_response = connection.sendcmd('EPSV')
                    info['epsv_support'] = True
                    info['epsv_response'] = epsv_response[:100]
                finally:
                    connection.sock.settimeout(old_timeout)
            else:
                info['epsv_support'] = False
        except:
            info['epsv_support'] = False
        
        # Get server statistics (if SITE STATS is supported) - with timeout
        print_status("  Getting server statistics...")
        try:
            if hasattr(connection, 'sock') and connection.sock:
                old_timeout = connection.sock.gettimeout()
                connection.sock.settimeout(3)
                try:
                    stats_response = connection.sendcmd('SITE STATS')
                    info['stats'] = stats_response[:500]  # Limit response
                finally:
                    connection.sock.settimeout(old_timeout)
            else:
                info['stats'] = None
        except:
            info['stats'] = None
        
        # Check for help command (with timeout)
        print_status("  Getting help information...")
        try:
            if hasattr(connection, 'sock') and connection.sock:
                old_timeout = connection.sock.gettimeout()
                connection.sock.settimeout(3)
                try:
                    help_response = connection.sendcmd('HELP')
                    info['help'] = help_response.split('\n')[:20]  # First 20 lines
                finally:
                    connection.sock.settimeout(old_timeout)
            else:
                info['help'] = []
        except:
            info['help'] = []
        
        return info
    
    def _get_permissions_info(self) -> dict:
        """Test and gather permission information"""
        perms = {
            'can_list': False,
            'can_read': False,
            'can_write': False,
            'can_delete': False,
            'can_mkdir': False,
            'can_rmdir': False,
            'can_rename': False
        }
        
        try:
            connection = self.open_ftp()
            
            # Set socket timeout
            if hasattr(connection, 'sock') and connection.sock:
                connection.sock.settimeout(5)
            
            # Test list
            print_status("  Testing list permission...")
            try:
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.retrlines('LIST', lambda x: None)  # Discard output
                perms['can_list'] = True
            except:
                pass
            
            # Test write (create and delete test file)
            print_status("  Testing write permission...")
            import time
            test_file = f'.test_write_{int(time.time())}'
            try:
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.storbinary(f'STOR {test_file}', b'test')
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.delete(test_file)
                perms['can_write'] = True
                perms['can_delete'] = True
            except:
                pass
            
            # Test mkdir
            print_status("  Testing directory creation...")
            test_dir = f'test_dir_{int(time.time())}'
            try:
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.mkd(test_dir)
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.rmd(test_dir)
                perms['can_mkdir'] = True
                perms['can_rmdir'] = True
            except:
                pass
            
            # Test rename
            print_status("  Testing rename permission...")
            try:
                test_file1 = f'.test1_{int(time.time())}'
                test_file2 = f'.test2_{int(time.time())}'
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.storbinary(f'STOR {test_file1}', b'test')
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.rename(test_file1, test_file2)
                if hasattr(connection, 'sock') and connection.sock:
                    connection.sock.settimeout(3)
                connection.delete(test_file2)
                perms['can_rename'] = True
            except:
                pass
            
        except Exception as e:
            perms['error'] = str(e)[:50]
        
        return perms
    
    def _parse_version(self, banner: str) -> dict:
        """Parse version information from banner"""
        version_info = {
            'server': 'Unknown',
            'version': 'Unknown',
            'os': 'Unknown'
        }
        
        # Common FTP server patterns
        patterns = {
            'vsftpd': r'vsftpd\s+([\d.]+)',
            'proftpd': r'ProFTPD\s+([\d.]+)',
            'pure-ftpd': r'Pure-FTPd\s*\[?([^\]]*)\]?',
            'filezilla': r'FileZilla\s+Server\s+([\d.]+)',
            'microsoft': r'Microsoft\s+FTP\s+Service',
            'wu-ftpd': r'wu-ftpd\s+([\d.]+)',
        }
        
        banner_lower = banner.lower()
        for server, pattern in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version_info['server'] = server.title().replace('-', '-')
                if match.groups() and match.group(1):
                    version_info['version'] = match.group(1).strip()
                else:
                    # For Pure-FTPd, try to extract version from banner
                    if 'pure-ftpd' in server:
                        version_match = re.search(r'\[([^\]]+)\]', banner)
                        if version_match:
                            version_info['version'] = version_match.group(1)
                break
        
        # Try to detect OS from system response
        return version_info
    
    def run(self):
        """Run the system information gathering"""
        try:
            print_info("=" * 70)
            print_info("FTP System Information Gathering")
            print_info("=" * 70)
            
            # Load session first to ensure it's available
            session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
            if session_id_value and hasattr(self, 'framework') and self.framework:
                if hasattr(self.framework, 'session_manager'):
                    session = self.framework.session_manager.get_session(session_id_value)
                    if session:
                        self.session = session
            
            # Get connection info (now that session is loaded)
            conn_info = self.get_ftp_connection_info()
            host = conn_info.get('host', 'unknown')
            port = conn_info.get('port', 21)
            username = conn_info.get('username', 'unknown')
            
            print_info(f"FTP Server: {host}:{port}")
            print_info(f"Username: {username}")
            print_info("")
            
            # Get FTP connection for banner and system info
            connection = self.open_ftp()
            
            # Get banner from connection
            print_status("Server Banner:")
            banner = self._get_banner(connection, host, port)
            print_info(f"  {banner}")
            
            # Parse version
            version_info = self._parse_version(banner)
            print_info("")
            print_status("Server Information:")
            print_info(f"  Server: {version_info['server']}")
            print_info(f"  Version: {version_info['version']}")
            print_info("")
            
            # Get system info (connection already obtained)
            print_status("System Information:")
            sys_info = self._get_system_info()
            
            # If we still don't have host info, try to get it from connection
            if host == 'unknown' and connection:
                try:
                    # Try to get host from connection socket
                    if hasattr(connection, 'sock') and connection.sock:
                        peer = connection.sock.getpeername()
                        if peer:
                            host = peer[0]
                            port = peer[1] if len(peer) > 1 else port
                            print_info(f"  Detected connection: {host}:{port}")
                except:
                    pass
            
            print_info(f"  System Type: {sys_info.get('system', 'Unknown')}")
            print_info(f"  Current Directory: {sys_info.get('current_directory', 'Unknown')}")
            print_info("")
            
            # Features
            features = sys_info.get('features', [])
            if features:
                print_status(f"Server Features ({len(features)}):")
                for feature in features[:30]:  # Limit to first 30
                    if feature.strip():
                        print_info(f"  - {feature.strip()}")
                if len(features) > 30:
                    print_info(f"  ... and {len(features) - 30} more")
            else:
                print_warning("  No features available or FEAT command not supported")
            print_info("")
            
            # Supported commands
            supported = sys_info.get('supported_commands', [])
            if supported:
                print_status("Supported Commands:")
                print_info(f"  {', '.join(supported)}")
            print_info("")
            
            # Passive mode support
            print_status("Passive Mode Support:")
            if sys_info.get('pasv_support'):
                print_success("  ✓ PASV (IPv4) supported")
            else:
                print_error("  ✗ PASV not supported")
            
            if sys_info.get('epsv_support'):
                print_success("  ✓ EPSV (IPv6) supported")
            else:
                print_info("  - EPSV not supported")
            print_info("")
            
            # Permissions
            print_status("User Permissions:")
            perms = self._get_permissions_info()
            
            perm_map = {
                'can_list': 'List directories',
                'can_read': 'Read files',
                'can_write': 'Write files',
                'can_delete': 'Delete files',
                'can_mkdir': 'Create directories',
                'can_rmdir': 'Remove directories',
                'can_rename': 'Rename files'
            }
            
            for perm_key, perm_name in perm_map.items():
                status = "✓" if perms.get(perm_key) else "✗"
                color_func = print_success if perms.get(perm_key) else print_error
                print_info(f"  {status} {perm_name}")
            print_info("")
            
            # Statistics (if available)
            if sys_info.get('stats'):
                print_status("Server Statistics:")
                stats_lines = sys_info['stats'].split('\n')[:10]
                for line in stats_lines:
                    if line.strip():
                        print_info(f"  {line.strip()}")
                print_info("")
            
            print_success("System information gathering complete!")
            
            return True
            
        except ProcedureError:
            raise
        except Exception as e:
            raise ProcedureError(FailureType.Unknown, f"Error gathering system information: {e}")
