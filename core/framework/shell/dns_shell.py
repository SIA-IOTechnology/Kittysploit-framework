#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS C2 shell - queue commands for the agent and view output received via DNS.
"""

from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning

class DNSShell(BaseShell):
    """DNS C2 shell - send commands via TXT response, view output from agent queries."""

    def __init__(self, session_id: str, session_type: str = "dns", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.listener = None
        self.domain = ""
        self.client_id = ""
        self.client_ip = ""

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'info': self._cmd_info,
            'run': self._cmd_run,
            'output': self._cmd_output,
            'output_clear': self._cmd_output_clear,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_listener()

    def _initialize_listener(self):
        """Get DNS listener from framework for this session."""
        try:
            if not self.framework or not hasattr(self.framework, 'session_manager'):
                return
            session = self.framework.session_manager.get_session(self.session_id)
            if not session or not session.data:
                return
            self.domain = session.data.get('domain', '')
            self.client_id = session.data.get('client_id', '')
            self.client_ip = session.data.get('client_ip', '')
            listener_id = session.data.get('listener_id')
            if listener_id and hasattr(self.framework, 'active_listeners'):
                self.listener = self.framework.active_listeners.get(listener_id)
        except Exception as e:
            print_warning(f"Could not initialize DNS listener: {e}")

    @property
    def shell_name(self) -> str:
        return "dns"

    @property
    def prompt_template(self) -> str:
        return f"dns [{self.client_id or self.session_id[:8]}]> "

    def get_prompt(self) -> str:
        return self.prompt_template

    def execute_command(self, command: str) -> Dict[str, Any]:
        if not command.strip():
            return {'output': '', 'status': 0, 'error': ''}
        self.add_to_history(command)
        parts = command.strip().split(None, 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        if cmd in self.builtin_commands:
            try:
                return self.builtin_commands[cmd](args)
            except Exception as e:
                return {'output': '', 'status': 1, 'error': str(e)}
        return {'output': '', 'status': 1, 'error': f"Unknown command: {cmd}. Use 'help' or 'run <cmd>'."}

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        help_text = """
DNS C2 Shell Commands:
======================
  run <command>     - Queue command for agent (agent gets it on next poll)
  output [N]        - Show last N lines of output from agent (default 50)
  output_clear      - Clear output buffer
  info              - Show session/domain/agent info
  help              - This help
  exit, quit        - Exit shell

Agent must query: poll.<client_id>.<domain> and result.<b64>.<client_id>.<domain>
"""
        return {'output': help_text.strip(), 'status': 0, 'error': ''}

    def _cmd_clear(self, args: str) -> Dict[str, Any]:
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
        return {'output': '', 'status': 0, 'error': ''}

    def _cmd_history(self, args: str) -> Dict[str, Any]:
        history = self.get_history()
        if not history:
            return {'output': 'No history', 'status': 0, 'error': ''}
        return {'output': '\n'.join(f"{i+1:4d}  {c}" for i, c in enumerate(history)), 'status': 0, 'error': ''}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        lines = [
            f"Domain:   {self.domain or '(unknown)'}",
            f"Client:   {self.client_id or '(unknown)'}",
            f"IP:       {self.client_ip or '(unknown)'}",
            f"Session:  {self.session_id}",
        ]
        return {'output': '\n'.join(lines), 'status': 0, 'error': ''}

    def _cmd_run(self, args: str) -> Dict[str, Any]:
        if not self.listener:
            return {'output': '', 'status': 1, 'error': 'DNS listener not available'}
        if not args.strip():
            return {'output': '', 'status': 1, 'error': 'Usage: run <command>'}
        if not hasattr(self.listener, 'set_pending_command'):
            return {'output': '', 'status': 1, 'error': 'Listener does not support set_pending_command'}
        self.listener.set_pending_command(self.session_id, args.strip())
        return {'output': 'Command queued. Agent will receive it on next DNS poll.', 'status': 0, 'error': ''}

    def _cmd_output(self, args: str) -> Dict[str, Any]:
        if not self.listener or not hasattr(self.listener, 'get_output_lines'):
            return {'output': '(no output)', 'status': 0, 'error': ''}
        try:
            n = 50
            if args.strip().isdigit():
                n = min(int(args.strip()), 500)
        except ValueError:
            n = 50
        lines = self.listener.get_output_lines(self.session_id, last_n=n)
        if not lines:
            return {'output': '(no output from agent yet)', 'status': 0, 'error': ''}
        return {'output': '\n'.join(lines), 'status': 0, 'error': ''}

    def _cmd_output_clear(self, args: str) -> Dict[str, Any]:
        if self.listener and hasattr(self.listener, '_received_output'):
            self.listener._received_output[self.session_id] = []
        return {'output': 'Output buffer cleared.', 'status': 0, 'error': ''}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}

    def get_available_commands(self) -> List[str]:
        return list(self.builtin_commands.keys())
