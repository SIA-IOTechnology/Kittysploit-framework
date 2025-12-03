#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FTP Wrapper for Pivoting
Routes FTP connections through SOCKS proxy
"""

import ftplib
import socket
from typing import Optional

# Try to import socks
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    # Create dummy constants
    class DummySocks:
        SOCKS4 = 1
        SOCKS5 = 2
    socks = DummySocks()

class ProxiedFTP(ftplib.FTP):
    """FTP client that routes through SOCKS proxy"""
    
    def __init__(self, host='', user='', passwd='', acct='', 
                 proxy_host=None, proxy_port=None, proxy_type=socks.SOCKS5, **kwargs):
        """
        Initialize FTP connection with SOCKS proxy support
        
        Args:
            proxy_host: SOCKS proxy host
            proxy_port: SOCKS proxy port
            proxy_type: SOCKS proxy type (socks.SOCKS4 or socks.SOCKS5)
        """
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_type = proxy_type
        self._use_proxy = proxy_host is not None and proxy_port is not None
        
        # Store original socket
        self._original_socket = socket.socket
        
        if self._use_proxy:
            # Create socket with proxy
            def create_proxied_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
                sock = socket.socket(family, type, proto, fileno)
                sock.set_proxy(self._proxy_type, self._proxy_host, self._proxy_port)
                return sock
            
            # Temporarily replace socket.socket
            socket.socket = create_proxied_socket
        
        try:
            super().__init__(host, user, passwd, acct, **kwargs)
        finally:
            # Restore original socket
            if self._use_proxy:
                socket.socket = self._original_socket
    
    def connect(self, host='', port=0, timeout=-999, source_address=None):
        """Connect to FTP server through proxy"""
        if self._use_proxy:
            # Create proxied socket
            def create_proxied_socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
                sock = socket.socket(family, type, proto, fileno)
                sock.set_proxy(self._proxy_type, self._proxy_host, self._proxy_port)
                return sock
            
            # Temporarily replace socket.socket
            socket.socket = create_proxied_socket
        
        try:
            return super().connect(host, port, timeout, source_address)
        finally:
            # Restore original socket
            if self._use_proxy:
                socket.socket = self._original_socket

def get_ftp_with_proxy(proxy_host=None, proxy_port=None, proxy_type=socks.SOCKS5):
    """Get FTP class configured with proxy"""
    if proxy_host and proxy_port:
        class FTPWithProxy(ProxiedFTP):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, proxy_host=proxy_host, proxy_port=proxy_port, 
                                proxy_type=proxy_type, **kwargs)
        return FTPWithProxy
    return ftplib.FTP

