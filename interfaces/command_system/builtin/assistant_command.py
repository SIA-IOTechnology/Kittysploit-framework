#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Toggle the operator assistant (contextual next-action suggestions)."""

from typing import List

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error


class AssistantCommand(BaseCommand):
    """Enable or disable contextual next-action suggestions."""

    @property
    def name(self) -> str:
        return "assistant"

    @property
    def description(self) -> str:
        return "Enable or disable contextual next-action suggestions"

    @property
    def usage(self) -> str:
        return "assistant [on|off|status]"

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Options:
    on      - Enable assistant suggestions
    off     - Disable assistant suggestions
    status  - Show current assistant status

When enabled, after relevant commands (run, check, sessions, new sessions)
the assistant prints a cyan framed panel with suggested next actions.
This is not a chatbot: it only suggests, never auto-executes.

Examples:
    assistant on
    assistant off
    assistant status
        """

    def get_subcommands(self) -> List[str]:
        return ["on", "off", "status", "enable", "disable"]

    def execute(self, args, **kwargs) -> bool:
        if not hasattr(self.framework, "assistant_enabled"):
            self.framework.assistant_enabled = False

        if len(args) == 0:
            status = "enabled" if self.framework.assistant_enabled else "disabled"
            print_info(f"Assistant: {status}")
            return True

        action = str(args[0]).lower()

        if action in ("--help", "-h", "help"):
            print_info(self.help_text)
            return True

        if action in ("on", "enable", "true", "1"):
            self.framework.assistant_enabled = True
            print_success("Assistant enabled — suggestions will appear after relevant commands")
            return True

        if action in ("off", "disable", "false", "0"):
            self.framework.assistant_enabled = False
            print_success("Assistant disabled")
            return True

        if action in ("status", "show"):
            status = "enabled" if self.framework.assistant_enabled else "disabled"
            print_info(f"Assistant: {status}")
            return True

        print_error(f"Unknown action: {action}")
        print_info(f"Usage: {self.usage}")
        print_info("Use 'assistant --help' for more information")
        return False
