#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shortcut command to open Metasploit from KittySploit.
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_error


class MsfCommand(BaseCommand):
    """Toggle KittySploit into Metasploit-integrated context."""

    @property
    def name(self) -> str:
        return "msf"

    @property
    def description(self) -> str:
        return "Enable or disable integrated Metasploit context inside KittySploit"

    @property
    def usage(self) -> str:
        return "msf [on|off|status] [--path /path/to/msfconsole]"

    @property
    def help_text(self) -> str:
        return (
            "Open Metasploit directly from KittySploit.\n"
            f"Usage: {self.usage}\n\n"
            "Examples:\n"
            "  msf on\n"
            "  msf off\n"
            "  msf status\n"
            "  msf on --path /opt/metasploit-framework/bin/msfconsole\n\n"
            "When enabled, the prompt shows `:msf` and `use/show/set/run/back`\n"
            "target Metasploit while the other KittySploit commands remain available.\n"
        )

    def execute(self, args, **kwargs) -> bool:
        plugin_manager = getattr(self.framework, "plugin_manager", None)
        if plugin_manager is None:
            print_error("Plugin manager not available")
            return False

        command_args = ["context"]
        if args:
            command_args.extend(args)
        else:
            command_args.append("on")
        return plugin_manager.execute_plugin("metasploit", command_args)
