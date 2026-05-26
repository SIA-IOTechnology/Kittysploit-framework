#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Route command implementation — Metasploit-style subnet routing through sessions.
"""

from typing import List
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_warning


class RouteCommand(BaseCommand):
    """Command to manage pivot routes through active sessions."""

    @property
    def name(self) -> str:
        return "route"

    @property
    def description(self) -> str:
        return "Manage subnet routes through active sessions for pivoting"

    @property
    def usage(self) -> str:
        return "route [add|del|list|flush|help] [options]"

    @property
    def help_text(self) -> str:
        return """
Manage subnet routes through active sessions for pivoting.

Usage: route [add|del|list|flush|help] [options]

Route traffic destined for a given subnet through an active session's
SOCKS proxy.  Once a route is added, all framework modules (scanners,
exploits, etc.) transparently send traffic for that subnet through the
compromised host.

Subcommands:
    add  <subnet>[/cidr] <session_id> [proxy_port]  Add a route
    del  <subnet>[/cidr] [session_id]                Remove a route
    list                                             Show routing table
    print                                            Alias for list
    flush                                            Remove all routes
    help                                             Show this help

Arguments:
    subnet/cidr   Target network in CIDR notation (e.g. 10.10.0.0/16)
                  A single IP without /cidr defaults to /32.
    session_id    UUID of the session to route through.
    proxy_port    Local SOCKS proxy port for this session (default: 1080).

Examples:
    route add 192.168.1.0/24 abc123-def4       Route 192.168.1.0/24 via session
    route add 10.0.0.0/8 abc123-def4 9050      ... with custom proxy port
    route add 172.16.5.10 abc123-def4           Route a single host
    route del 192.168.1.0/24                    Remove route for subnet
    route del 192.168.1.0/24 abc123-def4        Remove route for specific session
    route list                                  Show all routes
    route flush                                 Remove every route

Notes:
    - A SOCKS proxy must be running on the compromised host for the route
      to work.  Use 'post/shell/linux/pivot/socks_proxy' to deploy one.
    - The socket wrapper is automatically (re)installed when you add a
      route so that all TCP connections honor the routing table.
    - Routes use longest-prefix matching: more specific subnets win.
        """

    # --------------------------------------------------------------------- #

    def execute(self, args: List[str], **kwargs) -> bool:
        if not self._check_route_manager():
            return False

        if not args:
            return self._list_routes()

        subcommand = args[0].lower()

        if subcommand == "add":
            return self._add_route(args[1:])
        elif subcommand in ("del", "remove", "rm"):
            return self._del_route(args[1:])
        elif subcommand in ("list", "print"):
            return self._list_routes()
        elif subcommand == "flush":
            return self._flush_routes()
        elif subcommand == "help":
            self.show_help()
            return True
        else:
            print_error(f"Unknown subcommand: {subcommand}")
            print_info("Available subcommands: add, del, list, flush, help")
            return False

    # --------------------------------------------------------------------- #
    # Helpers
    # --------------------------------------------------------------------- #

    def _check_route_manager(self) -> bool:
        if not hasattr(self.framework, 'route_manager') or self.framework.route_manager is None:
            print_error("Route manager not available on this framework instance")
            return False
        return True

    def _ensure_socket_wrapper(self):
        """(Re-)install the socket wrapper so new routes are honored."""
        try:
            from lib.pivot.socket_wrapper import install_socket_wrapper
            install_socket_wrapper(self.framework)
        except Exception as exc:
            print_warning(f"Could not install socket wrapper: {exc}")

    # --------------------------------------------------------------------- #
    # Subcommands
    # --------------------------------------------------------------------- #

    def _add_route(self, args: List[str]) -> bool:
        if len(args) < 2:
            print_error("Usage: route add <subnet>[/cidr] <session_id> [proxy_port]")
            return False

        subnet = args[0]
        session_id = args[1]
        proxy_port = 1080
        if len(args) >= 3:
            try:
                proxy_port = int(args[2])
            except ValueError:
                print_error(f"Invalid proxy port: {args[2]}")
                return False

        success = self.framework.route_manager.add_route(
            subnet_str=subnet,
            session_id=session_id,
            proxy_host='127.0.0.1',
            proxy_port=proxy_port,
        )

        if success:
            self._ensure_socket_wrapper()
            print_info("Tip: make sure a SOCKS proxy is running for this session.")
            print_info("     Use 'post/shell/linux/pivot/socks_proxy' to deploy one.")

        return success

    def _del_route(self, args: List[str]) -> bool:
        if len(args) < 1:
            print_error("Usage: route del <subnet>[/cidr] [session_id]")
            return False

        subnet = args[0]
        session_id = args[1] if len(args) >= 2 else None

        success = self.framework.route_manager.remove_route(subnet, session_id)

        if success and not self.framework.route_manager.has_routes():
            from lib.pivot.socket_wrapper import uninstall_socket_wrapper
            uninstall_socket_wrapper()
            print_info("No routes remaining — socket wrapper removed.")

        return success

    def _list_routes(self) -> bool:
        rows = self.framework.route_manager.list_routes()

        if not rows:
            print_info("No routes configured.")
            print_info("Use 'route add <subnet>/<cidr> <session_id>' to add one.")
            return True

        print_info("")
        print_info("Routing Table")
        print_info("=" * 100)
        print_info(f"{'#':<4} {'Subnet':<22} {'Gateway':<28} {'Session':<38} {'Info'}")
        print_info("-" * 100)

        for r in rows:
            status = "" if r['active'] else " [inactive]"
            print_info(
                f"{r['id']:<4} "
                f"{r['subnet']:<22} "
                f"{r['gateway']:<28} "
                f"{r['session_id'][:36]:<38} "
                f"{r['session_info']}{status}"
            )

        print_info("-" * 100)
        print_info(f"Total: {len(rows)} route(s)")
        print_info("")
        return True

    def _flush_routes(self) -> bool:
        self.framework.route_manager.flush()

        from lib.pivot.socket_wrapper import uninstall_socket_wrapper
        uninstall_socket_wrapper()
        print_info("Socket wrapper removed.")

        return True
