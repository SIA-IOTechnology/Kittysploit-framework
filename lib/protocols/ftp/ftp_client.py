import ftplib
from typing import Optional, Any
from core.framework.option.option_string import OptString
from core.framework.option.option_port import OptPort
from core.framework.option.option_integer import OptInteger
from core.framework.base_module import BaseModule

class FTPOptions:
    """
    Standard FTP Options for Auxiliary/Exploit modules.
    Do NOT use this for Post modules (they use Session).
    """
    def __init__(self):
        self.rhost = OptString("", "Target IP or hostname", True)
        self.rport = OptPort(21, "Target port", True)
        self.ftp_user = OptString("anonymous", "FTP username", True)
        self.ftp_password = OptString("anonymous", "FTP password", True)
        self.timeout = OptInteger(10, "Connection timeout in seconds", True)

class FTPClientMixin:
    """
    FTP Client Logic (Mixin).
    Provides methods to interact with FTP (connect, list, download, etc.).
    Can work with an existing Session OR standalone options.
    """
    
    def get_ftp_connection(self) -> Any:
        """
        Get an FTP connection object.
        Auto-detects context (Session vs Direct).
        """
        # 1. Mode Post-Exploitation (Session)
        # If session is not set but we have session_id, try to get it from session_manager
        if not (hasattr(self, 'session') and self.session):
            # Try to get session from session_id if available (for Post modules)
            if hasattr(self, 'session_id'):
                session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
                if session_id_value and hasattr(self, 'framework') and self.framework:
                    if hasattr(self.framework, 'session_manager'):
                        session = self.framework.session_manager.get_session(session_id_value)
                        if session:
                            self.session = session
        
        if hasattr(self, 'session') and self.session:
            if hasattr(self, 'print_status'):
                session_id = getattr(self.session, 'session_id', getattr(self.session, 'id', 'unknown'))
                self.print_status(f"Using session {session_id} for FTP operations...")
            return self._get_session_client()
            
        # 2. Mode Direct (Auxiliary/Scanner)
        # On cherche les attributs définis par FTPOptions ou manuellement
        host = getattr(self, 'rhost', getattr(self, 'target', None))
        
        if host:
            # Si c'est une Option (objet), on prend sa valeur, sinon la valeur directe
            host_val = host.value if hasattr(host, 'value') else host
            
            if hasattr(self, 'print_status'):
                self.print_status(f"Connecting directly to {host_val}...")
            return self._get_direct_client(host_val)
            
        raise RuntimeError("Could not determine connection mode: No active session and no target/rhost specified.")

    def _get_direct_client(self, host: str):
        """Create a direct ftplib connection"""
        # Helper pour récupérer la valeur d'une option ou un attribut brut
        def get_val(name, default=None):
            attr = getattr(self, name, default)
            return attr.value if hasattr(attr, 'value') else attr

        port = get_val('rport', get_val('port', 21))
        user = get_val('ftp_user', get_val('username', 'anonymous'))
        password = get_val('ftp_password', get_val('password', 'anonymous'))
        timeout = get_val('timeout', 10)
        
        try:
            # Check if proxy is configured via framework
            proxy_host = None
            proxy_port = None
            proxy_type = None
            
            if hasattr(self, 'framework') and self.framework:
                if hasattr(self.framework, 'is_proxy_enabled') and self.framework.is_proxy_enabled():
                    proxy_url = self.framework.get_proxy_url()
                    if proxy_url and proxy_url.startswith('socks'):
                        import re
                        match = re.match(r'socks(\d)://([^:]+):(\d+)', proxy_url)
                        if match:
                            proxy_type_num = int(match.group(1))
                            proxy_host = match.group(2)
                            proxy_port = int(match.group(3))
                            
                            try:
                                import socks
                                proxy_type = socks.SOCKS5 if proxy_type_num == 5 else socks.SOCKS4
                            except ImportError:
                                if hasattr(self, 'print_warning'):
                                    self.print_warning("PySocks not installed - FTP proxy not available")
                                proxy_host = None
            
            # Create FTP connection with proxy if available
            if proxy_host and proxy_port and proxy_type:
                from lib.pivot.ftp_wrapper import ProxiedFTP
                ftp = ProxiedFTP(proxy_host=proxy_host, proxy_port=proxy_port, proxy_type=proxy_type)
            else:
                ftp = ftplib.FTP()
            
            ftp.connect(host, int(port), timeout=int(timeout))
            ftp.login(user, password)
            return ftp
        except Exception as e:
            if hasattr(self, 'print_error'):
                self.print_error(f"FTP Connection failed: {e}")
            raise e

    def _get_session_client(self):
        """Retrieve client from session."""
        # Try direct connection attribute
        if hasattr(self.session, 'connection') and self.session.connection:
            return self.session.connection
        if hasattr(self.session, 'client') and self.session.client:
            return self.session.client
        
        # Try to get connection from session.data (for FTP listener sessions)
        if hasattr(self.session, 'data') and self.session.data:
            if isinstance(self.session.data, dict):
                # Check for connection in data dict
                if 'connection' in self.session.data and self.session.data['connection']:
                    return self.session.data['connection']
                # Also check if data itself is the connection (for some session types)
                from ftplib import FTP
                if isinstance(self.session.data, FTP):
                    return self.session.data
        
        # Try to get connection from listener (for FTP listener sessions)
        if hasattr(self, 'framework') and self.framework:
            if hasattr(self.session, 'data') and self.session.data:
                listener_id = self.session.data.get('listener_id') if isinstance(self.session.data, dict) else None
                if listener_id and hasattr(self.framework, 'active_listeners'):
                    listener = self.framework.active_listeners.get(listener_id)
                    if listener and hasattr(listener, '_session_connections'):
                        session_id = getattr(self.session, 'session_id', getattr(self.session, 'id', None))
                        if session_id:
                            connection = listener._session_connections.get(session_id)
                            if connection:
                                return connection
        
        # Last resort: return session itself (might be the connection)
        return self.session

    # --- Common FTP Operations (Wrappers) ---

    def list_files(self, path: str = ".") -> list:
        """List files in directory (returns list of dicts)"""
        conn = self.get_ftp_connection()
        results = []
        
        try:
            # Note: This is a basic implementation for ftplib
            # Session objects might have their own list_files method
            if hasattr(conn, 'list_files'):
                return conn.list_files(path)
            
            # Standard ftplib implementation
            original_cwd = conn.pwd()
            if path != ".":
                conn.cwd(path)
            
            lines = []
            conn.dir(lines.append)
            
            # Basic parsing (could be improved)
            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    is_dir = line.startswith('d')
                    name = ' '.join(parts[8:])
                    size = parts[4]
                    date = ' '.join(parts[5:8])
                    results.append({
                        'name': name,
                        'type': 'directory' if is_dir else 'file',
                        'size': size,
                        'date': date
                    })
            
            if path != ".":
                conn.cwd(original_cwd)
                
        except Exception as e:
            if hasattr(self, 'print_error'):
                self.print_error(f"Failed to list files: {e}")
            raise e
            
        return results

    def download_file(self, remote_path: str, local_path: str):
        """Download a file"""
        conn = self.get_ftp_connection()
        
        if hasattr(conn, 'download'):
            return conn.download(remote_path, local_path)
            
        with open(local_path, 'wb') as f:
            conn.retrbinary(f'RETR {remote_path}', f.write)

    def change_directory(self, path: str):
        """Change current directory"""
        conn = self.get_ftp_connection()
        conn.cwd(path)
    
    def open_ftp(self):
        """Alias for get_ftp_connection for compatibility"""
        return self.get_ftp_connection()
    
    def get_ftp_connection_info(self) -> dict:
        """Get FTP connection information from session or options"""
        info = {}
        
        # Try to load session if not already loaded (for Post modules)
        if not (hasattr(self, 'session') and self.session):
            if hasattr(self, 'session_id'):
                session_id_value = self.session_id.value if hasattr(self.session_id, 'value') else str(self.session_id)
                if session_id_value and hasattr(self, 'framework') and self.framework:
                    if hasattr(self.framework, 'session_manager'):
                        session = self.framework.session_manager.get_session(session_id_value)
                        if session:
                            self.session = session
        
        # If using session
        if hasattr(self, 'session') and self.session:
            # Try to get info from session.data (for FTP listener sessions)
            if hasattr(self.session, 'data') and self.session.data:
                if isinstance(self.session.data, dict):
                    info['host'] = self.session.data.get('host', 'unknown')
                    info['port'] = self.session.data.get('port', 21)
                    info['username'] = self.session.data.get('username', 'unknown')
                else:
                    # If data is not a dict, try other attributes
                    info['host'] = getattr(self.session, 'host', 'unknown')
                    info['port'] = getattr(self.session, 'port', 21)
                    info['username'] = getattr(self.session, 'username', 'unknown')
            elif hasattr(self.session, 'session_info'):
                session_info = self.session.session_info
                info['host'] = session_info.get('host', 'unknown')
                info['port'] = session_info.get('port', 21)
                info['username'] = session_info.get('username', 'unknown')
            elif hasattr(self.session, 'connection_info'):
                info = self.session.connection_info
            else:
                info['host'] = getattr(self.session, 'host', 'unknown')
                info['port'] = getattr(self.session, 'port', 21)
                info['username'] = getattr(self.session, 'username', 'unknown')
        else:
            # Direct mode
            def get_val(name, default=None):
                attr = getattr(self, name, default)
                return attr.value if hasattr(attr, 'value') else attr
            
            info['host'] = get_val('rhost', get_val('target', 'unknown'))
            info['port'] = get_val('rport', get_val('port', 21))
            info['username'] = get_val('ftp_user', get_val('username', 'unknown'))
        
        return info
    
    def get_current_directory(self) -> str:
        """Get current working directory"""
        conn = self.get_ftp_connection()
        return conn.pwd()
    
    def upload_file(self, local_path: str, remote_path: str):
        """Upload a file"""
        conn = self.get_ftp_connection()
        
        if hasattr(conn, 'upload'):
            return conn.upload(local_path, remote_path)
        
        with open(local_path, 'rb') as f:
            conn.storbinary(f'STOR {remote_path}', f)
    
    def get_file_size(self, remote_path: str) -> int:
        """Get file size"""
        conn = self.get_ftp_connection()
        
        if hasattr(conn, 'size'):
            return conn.size(remote_path)
        
        try:
            return conn.size(remote_path)
        except:
            return 0

class Ftp_client(BaseModule):
    ftp_host = OptString("", "Target IP or hostname", True)
    ftp_port = OptPort(21, "Target port", True)
    ftp_user = OptString("anonymous", "FTP username", True)
    ftp_password = OptString("anonymous", "FTP password", True)
    ftp_timeout = OptPort(10, "FTP timeout", True, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)

    def open_ftp(self):
        """Open FTP connection"""
        ftp = ftplib.FTP()
        ftp.connect(self.ftp_host.value, int(self.ftp_port.value), timeout=int(self.ftp_timeout.value))
        ftp.login(self.ftp_user.value, self.ftp_password.value)
        return ftp