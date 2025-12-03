#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Socket Wrapper for Pivoting
Intercepts all socket connections and routes them through SOCKS proxy
"""

import socket
import os
from typing import Optional, Tuple
from core.output_handler import print_info, print_warning

# Try to import socks (may not be available)
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

# Store original socket class
_original_socket = socket.socket

class ProxiedSocket:
    """Wrapper for socket that routes through SOCKS proxy"""
    
    _proxy_enabled = False
    _proxy_host = None
    _proxy_port = None
    _proxy_type = socks.SOCKS5 if SOCKS_AVAILABLE else 2
    
    @classmethod
    def configure_proxy(cls, enabled: bool, host: str = '127.0.0.1', port: int = 1080, proxy_type: int = socks.SOCKS5):
        """Configure SOCKS proxy for all socket connections"""
        cls._proxy_enabled = enabled
        cls._proxy_host = host
        cls._proxy_port = port
        cls._proxy_type = proxy_type
        
        if enabled:
            print_info(f"Socket proxy configured: {proxy_type}://{host}:{port}")
        else:
            print_info("Socket proxy disabled")
    
    @classmethod
    def create_socket(cls, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
        """Create a socket that routes through proxy if enabled"""
        sock = _original_socket(family, type, proto, fileno)
        
        if cls._proxy_enabled and cls._proxy_host and cls._proxy_port:
            try:
                sock.set_proxy(cls._proxy_type, cls._proxy_host, cls._proxy_port)
            except AttributeError:
                # If socks module is not available, try to install it or use alternative
                print_warning("socks module not available - installing...")
                try:
                    import subprocess
                    subprocess.check_call(['pip', 'install', 'PySocks', '--quiet'])
                    import socks
                    sock.set_proxy(cls._proxy_type, cls._proxy_host, cls._proxy_port)
                except:
                    print_warning("Could not configure SOCKS proxy for socket")
        
        return sock

def install_socket_wrapper(framework=None):
    """Install socket wrapper to intercept all socket connections"""
    try:
        # Check if socks module is available
        try:
            import socks
        except ImportError:
            print_warning("PySocks not installed. Installing...")
            try:
                import subprocess
                subprocess.check_call(['pip', 'install', 'PySocks', '--quiet'])
                import socks
            except:
                print_warning("Could not install PySocks - socket proxy will not work")
                return False
        
        # Configure proxy from framework if available
        if framework and hasattr(framework, 'is_proxy_enabled'):
            if framework.is_proxy_enabled():
                proxy_url = framework.get_proxy_url()
                
                if proxy_url and proxy_url.startswith('socks'):
                    # Parse proxy URL
                    import re
                    match = re.match(r'socks(\d)://([^:]+):(\d+)', proxy_url)
                    if match:
                        proxy_type = int(match.group(1))
                        proxy_host = match.group(2)
                        proxy_port = int(match.group(3))
                        
                        proxy_type_enum = socks.SOCKS5 if proxy_type == 5 else socks.SOCKS4
                        ProxiedSocket.configure_proxy(True, proxy_host, proxy_port, proxy_type_enum)
        
        # Create a wrapper class that extends socket.socket
        class ProxiedSocketClass(_original_socket):
            def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, fileno=None):
                super().__init__(family, type, proto, fileno)
                
                # Configure proxy if enabled
                if ProxiedSocket._proxy_enabled and ProxiedSocket._proxy_host and ProxiedSocket._proxy_port:
                    try:
                        self.set_proxy(ProxiedSocket._proxy_type, ProxiedSocket._proxy_host, ProxiedSocket._proxy_port)
                    except AttributeError:
                        # SOCKS not available
                        pass
        
        # Replace socket.socket class
        socket.socket = ProxiedSocketClass
        
        return True
        
    except Exception as e:
        print_warning(f"Could not install socket wrapper: {e}")
        return False

def uninstall_socket_wrapper():
    """Restore original socket class"""
    socket.socket = _original_socket
    ProxiedSocket.configure_proxy(False)

