#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shortcut command for the listen plugin.
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error


class ListenCommand(BaseCommand):
    """Netcat-like listener for accepting TCP connections."""

    @property
    def name(self) -> str:
        return "listen"

    @property
    def description(self) -> str:
        return "Netcat-like listener for accepting TCP connections"

    @property
    def usage(self) -> str:
        return "listen [-p PORT]"

    @property
    def help_text(self) -> str:
        return (
            "Start a TCP listener and relay stdin/stdout to connected clients.\n"
            f"Usage: {self.usage}\n\n"
            "Examples:\n"
            "  listen\n"
            "  listen -p 4444\n"
            "  listen --help\n\n"
            "Equivalent to: plugin run listen [options]\n"
        )

    def execute(self, args, **kwargs) -> bool:
        plugin_manager = getattr(self.framework, "plugin_manager", None)
        if plugin_manager is None:
            print_error("Plugin manager not available")
            return False

        return plugin_manager.execute_plugin("listen", list(args or []))
