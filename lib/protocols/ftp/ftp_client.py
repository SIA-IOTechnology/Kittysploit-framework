import ftplib
from typing import Optional, Any
from core.framework.option.option_string import OptString
from core.framework.option.option_port import OptPort
from core.framework.option.option_integer import OptInteger

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
        if hasattr(self, 'session') and self.session:
            if hasattr(self, 'print_status'):
                self.print_status(f"Using session {self.session.session_id} for FTP operations...")
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
        if hasattr(self.session, 'connection') and self.session.connection:
            return self.session.connection
        if hasattr(self.session, 'client') and self.session.client:
            return self.session.client
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
