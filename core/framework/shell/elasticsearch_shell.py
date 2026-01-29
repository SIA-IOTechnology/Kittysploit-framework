#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Elasticsearch shell implementation for Elasticsearch sessions.
"""

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, RequestError
from typing import Dict, Any, List, Optional
import json
from .base_shell import BaseShell
from core.output_handler import print_info, print_error, print_warning, print_success

class ElasticsearchShell(BaseShell):
    """Elasticsearch shell - search and manage indices"""

    def __init__(self, session_id: str, session_type: str = "elasticsearch", framework=None):
        super().__init__(session_id, session_type)
        self.framework = framework
        self.connection = None
        self.host = "localhost"
        self.port = 9200
        self.default_index = ""

        self.builtin_commands = {
            'help': self._cmd_help,
            'clear': self._cmd_clear,
            'history': self._cmd_history,
            'cat': self._cmd_cat,
            'indices': self._cmd_indices,
            'search': self._cmd_search,
            'get': self._cmd_get,
            'mapping': self._cmd_mapping,
            'info': self._cmd_info,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'disconnect': self._cmd_exit,
        }

        self._initialize_es_connection()

    def _initialize_es_connection(self):
        try:
            if not self.framework:
                return
            if hasattr(self.framework, 'session_manager'):
                session = self.framework.session_manager.get_session(self.session_id)
                if session and session.data:
                    self.host = session.data.get('host', 'localhost')
                    self.port = session.data.get('port', 9200)
                    listener_id = session.data.get('listener_id')
                    if listener_id and hasattr(self.framework, 'active_listeners'):
                        listener = self.framework.active_listeners.get(listener_id)
                        if listener and hasattr(listener, '_session_connections'):
                            conn = listener._session_connections.get(self.session_id)
                            if conn and isinstance(conn, Elasticsearch):
                                self.connection = conn
                                return
                    if 'connection' in session.data:
                        conn = session.data['connection']
                        if isinstance(conn, Elasticsearch):
                            self.connection = conn
        except Exception as e:
            print_warning(f"Could not initialize Elasticsearch connection: {e}")

    @property
    def shell_name(self) -> str:
        return "elasticsearch"

    @property
    def prompt_template(self) -> str:
        return f"elasticsearch [{self.host}:{self.port}]> "

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
Elasticsearch Shell Commands:
=============================
  cat indices       - List indices (alias: indices)
  search <index> [query] - Search index (query: JSON or * for match_all)
  get <index>/<id>  - Get document by ID
  mapping <index>   - Get index mapping
  info              - Cluster info
  help              - This help
  exit, quit        - Exit shell
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

    def _cmd_cat(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Elasticsearch connection not available'}
        args_lower = (args or "").strip().lower()
        if args_lower == 'indices':
            return self._cmd_indices("")
        try:
            r = self.connection.cat.indices(format='text')
            return {'output': r if isinstance(r, str) else str(r), 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_indices(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Elasticsearch connection not available'}
        try:
            r = self.connection.cat.indices(format='text')
            return {'output': r if isinstance(r, str) else str(r), 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_search(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Elasticsearch connection not available'}
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: search <index> [query_json]'}
        parts = args.strip().split(None, 1)
        index = parts[0]
        query_str = parts[1] if len(parts) > 1 else '{"query": {"match_all": {}}}'
        try:
            body = json.loads(query_str) if query_str.strip() else {"query": {"match_all": {}}}
        except json.JSONDecodeError:
            return {'output': '', 'status': 1, 'error': 'Invalid JSON query'}
        try:
            r = self.connection.search(index=index, body=body, size=50)
            hits = r.get('hits', {}).get('hits', [])
            if not hits:
                return {'output': '(0 hits)', 'status': 0, 'error': ''}
            lines = [json.dumps(h.get('_source', h), default=str) for h in hits]
            return {'output': '\n'.join(lines), 'status': 0, 'error': ''}
        except RequestError as e:
            return {'output': '', 'status': 1, 'error': str(e)}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_get(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Elasticsearch connection not available'}
        if not args or '/' not in args:
            return {'output': '', 'status': 1, 'error': 'Usage: get <index>/<id>'}
        index, doc_id = args.strip().split('/', 1)
        try:
            r = self.connection.get(index=index.strip(), id=doc_id.strip())
            src = r.get('_source', r)
            return {'output': json.dumps(src, indent=2, default=str), 'status': 0, 'error': ''}
        except NotFoundError:
            return {'output': '(not found)', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_mapping(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Elasticsearch connection not available'}
        if not args:
            return {'output': '', 'status': 1, 'error': 'Usage: mapping <index>'}
        index = args.strip()
        try:
            r = self.connection.indices.get_mapping(index=index)
            return {'output': json.dumps(r, indent=2, default=str), 'status': 0, 'error': ''}
        except NotFoundError:
            return {'output': f'Index {index} not found', 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_info(self, args: str) -> Dict[str, Any]:
        if not self.connection:
            return {'output': '', 'status': 1, 'error': 'Elasticsearch connection not available'}
        try:
            r = self.connection.info()
            return {'output': json.dumps(r, indent=2, default=str), 'status': 0, 'error': ''}
        except Exception as e:
            return {'output': '', 'status': 1, 'error': str(e)}

    def _cmd_exit(self, args: str) -> Dict[str, Any]:
        self.is_active = False
        return {'output': 'Bye!', 'status': 0, 'error': ''}

    def get_available_commands(self) -> List[str]:
        return list(self.builtin_commands.keys())
