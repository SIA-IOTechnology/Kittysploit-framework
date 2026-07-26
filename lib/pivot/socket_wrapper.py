#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Socket Wrapper for Pivoting
Intercepts all socket connections and routes them through SOCKS proxy.

Supports two modes:
  1. Global proxy  – every TCP connection goes through a single SOCKS proxy.
  2. Route-based   – destination IPs are matched against a RouteManager
                     routing table; only matching traffic is proxied,
                     and different subnets can use different proxies.
"""

import socket
import subprocess
import sys
from typing import Optional, Tuple
from core.output_handler import print_info, print_warning, print_error

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    class DummySocks:
        SOCKS4 = 1
        SOCKS5 = 2
    socks = DummySocks()

_original_socket = socket.socket

# Singleton reference set by install_socket_wrapper
_route_manager = None


def _ensure_pysocks() -> bool:
    """Import or install PySocks into the active interpreter (venv-aware)."""
    global socks, SOCKS_AVAILABLE
    try:
        import socks as _socks
        socks = _socks
        SOCKS_AVAILABLE = True
        return True
    except ImportError:
        pass

    print_warning("PySocks not installed. Installing into current Python environment...")
    # Always use the running interpreter's pip — bare `pip` often hits system
    # Python (PEP 668) even when KittySploit was relaunched under ./venv.
    cmd = [sys.executable, "-m", "pip", "install", "PySocks", "--quiet"]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        print_warning(
            "pip blocked (externally-managed environment). "
            "Retrying with --break-system-packages..."
        )
        try:
            subprocess.check_call(cmd + ["--break-system-packages"])
        except Exception as exc:
            print_error(f"Could not install PySocks: {exc}")
            print_info(
                "Install manually, then restart KittySploit:\n"
                "  ./venv/bin/python -m pip install PySocks\n"
                "  # or: sudo apt install python3-socks"
            )
            return False
    except FileNotFoundError:
        print_error("pip is not available for this Python interpreter")
        print_info(
            "Install PySocks into the project venv: "
            "./venv/bin/python -m pip install PySocks"
        )
        return False

    try:
        import socks as _socks
        socks = _socks
        SOCKS_AVAILABLE = True
        print_info(f"PySocks installed for {sys.executable}")
        return True
    except ImportError:
        print_error("PySocks install reported success but import still fails")
        return False


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
            scheme = "socks5" if int(proxy_type) == int(getattr(socks, "SOCKS5", 2)) else "socks4"
            print_info(f"Socket proxy configured: {scheme}://{host}:{port}")
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
                if _ensure_pysocks():
                    try:
                        sock.set_proxy(cls._proxy_type, cls._proxy_host, cls._proxy_port)
                    except Exception:
                        print_warning("Could not configure SOCKS proxy for socket")
                else:
                    print_warning("Could not configure SOCKS proxy for socket")

        return sock


def _resolve_proxy_for_address(address) -> Optional[Tuple[int, str, int]]:
    """
    Check the routing table for *address* (host, port).
    Returns ``(proxy_type, proxy_host, proxy_port)`` or ``None``.
    """
    global _route_manager
    if _route_manager is None or not _route_manager.has_routes():
        return None

    host = address[0] if isinstance(address, (tuple, list)) else address
    if not isinstance(host, str):
        return None

    # Resolve hostname to IP for route matching
    try:
        import ipaddress
        ipaddress.IPv4Address(host)
        ip_str = host
    except ValueError:
        try:
            ip_str = _original_socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        except Exception:
            return None

    return _route_manager.get_proxy_for_ip(ip_str)


def install_socket_wrapper(framework=None):
    """
    Install socket wrapper to intercept all socket connections.

    When a RouteManager with active routes is present on *framework*,
    the wrapper performs per-connection route lookups.  Otherwise it
    falls back to the global ProxiedSocket proxy (or Tor).
    """
    global _route_manager
    try:
        if not _ensure_pysocks():
            print_warning("Could not install PySocks - socket proxy will not work")
            return False

        import socks as _socks

        # Grab the route manager if the framework exposes one
        if framework and hasattr(framework, 'route_manager'):
            _route_manager = framework.route_manager

        # Configure global proxy from framework (Tor first, then regular)
        if framework:
            if hasattr(framework, 'is_tor_enabled') and framework.is_tor_enabled():
                tor_proxy_url = framework.tor_manager.get_tor_proxy_url()
                if tor_proxy_url:
                    import re
                    match = re.match(r'socks(\d)://([^:]+):(\d+)', tor_proxy_url)
                    if match:
                        proxy_type = int(match.group(1))
                        proxy_host = match.group(2)
                        proxy_port = int(match.group(3))
                        proxy_type_enum = _socks.SOCKS5 if proxy_type == 5 else _socks.SOCKS4
                        ProxiedSocket.configure_proxy(True, proxy_host, proxy_port, proxy_type_enum)
                        # Still install the patched class (below) for route support
            elif hasattr(framework, 'is_proxy_enabled') and framework.is_proxy_enabled():
                proxy_url = framework.get_proxy_url()
                if proxy_url and proxy_url.startswith('socks'):
                    import re
                    match = re.match(r'socks(\d)://([^:]+):(\d+)', proxy_url)
                    if match:
                        proxy_type = int(match.group(1))
                        proxy_host = match.group(2)
                        proxy_port = int(match.group(3))
                        proxy_type_enum = _socks.SOCKS5 if proxy_type == 5 else _socks.SOCKS4
                        ProxiedSocket.configure_proxy(True, proxy_host, proxy_port, proxy_type_enum)

        class RoutedSocketClass(_socks.socksocket):
            """
            A socksocket subclass that checks the routing table on each
            ``connect()`` call so that different destinations can use
            different SOCKS proxies.
            """
            def connect(self, address):
                route_proxy = _resolve_proxy_for_address(address)
                if route_proxy:
                    ptype, phost, pport = route_proxy
                    self.set_proxy(ptype, phost, pport)
                elif ProxiedSocket._proxy_enabled:
                    self.set_proxy(
                        ProxiedSocket._proxy_type,
                        ProxiedSocket._proxy_host,
                        ProxiedSocket._proxy_port,
                    )
                super().connect(address)

        socket.socket = RoutedSocketClass
        return True

    except Exception as e:
        print_warning(f"Could not install socket wrapper: {e}")
        return False


def uninstall_socket_wrapper():
    """Restore original socket class"""
    global _route_manager
    socket.socket = _original_socket
    ProxiedSocket.configure_proxy(False)
    _route_manager = None
