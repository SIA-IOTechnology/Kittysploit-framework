#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LDAP shell implementation for LDAP directory sessions.
"""

from ldap3 import Connection, SUBTREE, LEVEL
from ldap3.core.exceptions import LDAPException
from typing import Dict, Any, List, Optional
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class LDAPShell(BaseShell):
    """LDAP shell - search and browse directory"""

    def __init__(self, session_id: str, session_type: str = "ldap", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.host = "localhost"
        self.port = 389
        self.base_dn = ""
        self.search_scope = SUBTREE

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'whoami': self._cmd_whoami,
            'base': self._cmd_base,
            'search': self._cmd_search,
            'list': self._cmd_list,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_ldap_connection()

    def _initialize_ldap_connection(self):
        """Initialize LDAP connection from session/listener"""
        try:
            if not self.framework:
                return
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session and session.data:
                    self.host = session.data.get('host', 'localhost')
                    self.port = session.data.get('port', 389)
                    self.base_dn = session.data.get('base_dn', '')
                    listener_id = session.data.get('listener_id')
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            conn = listener._session_connections.get(self.session_id)
                            if conn and isinstance(conn, Connection):
                                self.connection = conn
                                return
                    if 'connection' in session.data:
                        conn = session.data['connection']
                        if isinstance(conn, Connection):
                            self.connection = conn
        except Exception as e:
            print_warning(f"Could not initialize LDAP connection: {e}")

    @property
    def shell_name(self) -> str:
        return "ldap"

    @property
    def prompt_template(self) -> str:
        base = self.base_dn[:30] + "..." if len(self.base_dn) > 30 else (self.base_dn or "(no base)")
        return f"ldap [{self.host}:{self.port}]> "

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
        return {'output': '', 'status': 1, 'error': f'Unknown command: {cmd}. Type help.'}

    def _cmd_help(self, args: str) -> Dict[str, Any]:
        help_text = """
LDAP Shell Commands:
====================
  whoami           - Show current bind DN
  base [dn]        - Get/set default search base DN
  search <filter>   - Search with filter (e.g. (objectClass=*))
  list [base]      - List entries at base (one level)
  help             - This help
  exit, quit       - Exit shell

Examples:
  whoami
  base dc=example,dc=com
  search (objectClass=person)
  search (sAMAccountName=admin*)
  list
  list ou=Users,dc=example,dc=com
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

    def _cmd_whoami(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'LDAP connection not available'}
        try:
            result = self.connection.extend.standard.who_am_i()
            return {'output': result or '(anonymous)', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '(anonymous)', 'status': 0, 'error': ''}

    def _cmd_base(self, args: str) -> Dict[str, Any]:
        if args:
            self.base_dn = args.strip()
            return {'output': f'base_dn = {self.base_dn}', 'status': 0, 'error': ''}
        return {'output': self.base_dn or '(not set)', 'status': 0, 'error': ''}

    def _cmd_search(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'LDAP connection not available'}
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: search <filter> [base_dn]'}
        parts = args.strip().split(None, 1)
        search_filter = parts[0]
        base = parts[1].strip() if len(parts) > 1 else self.base_dn
        if not base:
            return {'output': '', 'status': 1, 'error': 'No base DN. Set with: base dc=example,dc=com'}
        try:
            self.connection.search(
                base,
                search_filter,
                search_scope=SUBTREE,
                attributes=['*']
            )
            if not self.connection.entries:
                return {'output': '(no results)', 'status': 0, 'error': ''}
            lines = []
            for entry in self.connection.entries:
                lines.append(f"dn: {entry.entry_dn}")
                for attr in entry.entry_attributes_as_dict:
                    vals = entry.entry_attributes_as_dict[attr]
                    if isinstance(vals, list):
                        for v in vals:
                            lines.append(f"  {attr}: {v}")
                    else:
                        lines.append(f"  {attr}: {vals}")
                lines.append('')
            return {'output': '\n'.join(lines).strip(), 'status': 0, 'error': ''}
        except LDAPException as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_list(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'LDAP connection not available'}
        base = args.strip() if args else self.base_dn
        if not base:
            return {'output': '', 'status': 1, 'error': 'Usage: list [base_dn] or set base first'}
        try:
            self.connection.search(
                base,
                '(objectClass=*)',
                search_scope=LEVEL,
                attributes=['dn', 'objectClass']
            )
            if not self.connection.entries:
                return {'output': '(no entries)', 'status': 0, 'error': ''}
            lines = [e.entry_dn for e in self.connection.entries]
            return {'output': '\n'.join(lines), 'status': 0, 'error': ''}
        except LDAPException as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        if self.connection:
            try:
                self.connection.unbind()
            except Exception:
                pass
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}

    def get_available_commands(self) -> List[str]:
        return list(self.builtin_commands.keys())
