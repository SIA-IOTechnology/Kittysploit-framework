#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Route Manager for Pivoting
Manages a routing table that maps subnets to sessions with SOCKS proxies,
similar to Metasploit's 'route' command.
"""

import ipaddress
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from core.output_handler import print_info, print_success, print_error, print_warning


@dataclass
class Route:
    """A single routing table entry."""
    subnet: ipaddress.IPv4Network
    session_id: str
    proxy_host: str = '127.0.0.1'
    proxy_port: int = 1080
    proxy_type: int = 2  # SOCKS5
    active: bool = True
    auto_deployed: bool = False


class RouteManager:
    """
    Manages subnet-based routing through compromised sessions.

    Traffic destined for a routed subnet is transparently forwarded through
    the SOCKS proxy associated with the corresponding session.
    """

    def __init__(self, framework=None):
        self.framework = framework
        self._routes: List[Route] = []
        self._lock = threading.Lock()

    @property
    def routes(self) -> List[Route]:
        with self._lock:
            return list(self._routes)

    def add_route(self, subnet_str: str, session_id: str,
                  proxy_host: str = '127.0.0.1', proxy_port: int = 1080,
                  proxy_type: int = 2) -> bool:
        """
        Add a route for *subnet_str* through *session_id*.

        Args:
            subnet_str: CIDR notation (e.g. "192.168.1.0/24") or single host.
            session_id: UUID of the session to route through.
            proxy_host: Local address of the SOCKS proxy for this session.
            proxy_port: Local port of the SOCKS proxy for this session.
            proxy_type: 1 = SOCKS4, 2 = SOCKS5.

        Returns:
            True on success.
        """
        try:
            if '/' not in subnet_str:
                subnet_str += '/32'
            network = ipaddress.IPv4Network(subnet_str, strict=False)
        except ValueError as exc:
            print_error(f"Invalid subnet: {subnet_str} ({exc})")
            return False

        if self.framework:
            session = self.framework.session_manager.get_session(session_id)
            if not session:
                print_error(f"Session not found: {session_id}")
                return False

        with self._lock:
            for r in self._routes:
                if r.subnet == network and r.session_id == session_id:
                    print_warning(f"Route already exists: {network} -> session {session_id}")
                    return False
            route = Route(
                subnet=network,
                session_id=session_id,
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                proxy_type=proxy_type,
            )
            self._routes.append(route)

        print_success(f"Route added: {network} -> session {session_id} "
                      f"(via socks{'5' if proxy_type == 2 else '4'}://{proxy_host}:{proxy_port})")
        return True

    def remove_route(self, subnet_str: str, session_id: Optional[str] = None) -> bool:
        """
        Remove a route.  If *session_id* is given, only the route for that
        exact (subnet, session) pair is removed; otherwise all routes matching
        the subnet are removed.
        """
        try:
            if '/' not in subnet_str:
                subnet_str += '/32'
            network = ipaddress.IPv4Network(subnet_str, strict=False)
        except ValueError as exc:
            print_error(f"Invalid subnet: {subnet_str} ({exc})")
            return False

        removed = False
        with self._lock:
            before = len(self._routes)
            if session_id:
                self._routes = [
                    r for r in self._routes
                    if not (r.subnet == network and r.session_id == session_id)
                ]
            else:
                self._routes = [r for r in self._routes if r.subnet != network]
            removed = len(self._routes) < before

        if removed:
            print_success(f"Route removed: {network}"
                          + (f" (session {session_id})" if session_id else ""))
        else:
            print_warning(f"No matching route found for {network}")
        return removed

    def remove_routes_for_session(self, session_id: str) -> int:
        """Remove every route that references *session_id*.  Returns count."""
        with self._lock:
            before = len(self._routes)
            self._routes = [r for r in self._routes if r.session_id != session_id]
            count = before - len(self._routes)
        if count:
            print_info(f"Removed {count} route(s) for session {session_id}")
        return count

    def flush(self) -> int:
        """Remove all routes.  Returns count."""
        with self._lock:
            count = len(self._routes)
            self._routes.clear()
        if count:
            print_success(f"Flushed {count} route(s)")
        else:
            print_info("Routing table already empty")
        return count

    def get_route_for_ip(self, ip_str: str) -> Optional[Route]:
        """
        Find the most-specific (longest prefix) route matching *ip_str*.
        Returns the Route or None if no route matches.
        """
        try:
            addr = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return None

        best: Optional[Route] = None
        with self._lock:
            for r in self._routes:
                if not r.active:
                    continue
                if addr in r.subnet:
                    if best is None or r.subnet.prefixlen > best.subnet.prefixlen:
                        best = r
        return best

    def get_proxy_for_ip(self, ip_str: str) -> Optional[Tuple[int, str, int]]:
        """
        Convenience wrapper: returns ``(proxy_type, proxy_host, proxy_port)``
        for a matching route, or *None* if the IP is not routed.
        """
        route = self.get_route_for_ip(ip_str)
        if route:
            return (route.proxy_type, route.proxy_host, route.proxy_port)
        return None

    def list_routes(self) -> List[Dict]:
        """Return a list of dicts for display purposes."""
        rows = []
        with self._lock:
            for idx, r in enumerate(self._routes):
                session_info = ""
                if self.framework:
                    session = self.framework.session_manager.get_session(r.session_id)
                    if session:
                        session_info = f"{session.host}:{session.port} ({session.session_type})"
                rows.append({
                    'id': idx,
                    'subnet': str(r.subnet),
                    'session_id': r.session_id,
                    'session_info': session_info,
                    'gateway': f"socks{'5' if r.proxy_type == 2 else '4'}://{r.proxy_host}:{r.proxy_port}",
                    'active': r.active,
                })
        return rows

    def has_routes(self) -> bool:
        with self._lock:
            return len(self._routes) > 0
