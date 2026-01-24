#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced command completer for KittySploit CLI
Provides context-aware completion and lightweight discovery helpers.
"""

import time
import difflib
import socket
from itertools import islice
from typing import List, Dict, Any, Optional, Iterable

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.filters import Filter

from interfaces.command_system.command_registry import CommandRegistry


class AdvancedCompleter(Completer):
    """Advanced completer that supports subcommands and context-aware completion."""

    CACHE_TTL = 5.0

    def __init__(self, command_registry: CommandRegistry, framework):
        self.command_registry = command_registry
        self.framework = framework

        self._command_cache: List[str] = []
        self._modules_cache: List[str] = []
        self._subcommand_cache: Dict[str, List[str]] = {}

        self._last_command_cache = 0.0
        self._last_module_cache = 0.0

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def refresh(self) -> None:
        """Invalidate cached data."""
        self._last_command_cache = 0.0
        self._last_module_cache = 0.0
        self._subcommand_cache.clear()

    # ------------------------------------------------------------------ #
    # Completion entry point
    # ------------------------------------------------------------------ #
    def get_completions(self, document: Document, complete_event) -> Iterable[Completion]:
        text = document.text_before_cursor
        tokens = text.split()
        ends_with_space = text.endswith(" ")
        current_word = tokens[-1] if tokens and not ends_with_space else ""

        if not tokens:
            yield from self._iter_command_completions("")
            return

        command = tokens[0]

        # Still typing the command itself
        if len(tokens) == 1 and not ends_with_space:
            yield from self._iter_command_completions(current_word)
            return

        # Contextual handling -------------------------------------------------
        if command == "use":
            partial = current_word if len(tokens) > 1 and not ends_with_space else ""
            yield from self._iter_module_completions(partial)
            return

        if command == "set":
            if len(tokens) == 1 and ends_with_space:
                yield from self._iter_set_option_completions("")
                return
            if len(tokens) == 1:
                yield from self._iter_command_completions(current_word)
                return
            if len(tokens) == 2 and not ends_with_space:
                yield from self._iter_set_option_completions(current_word)
                return
            option = tokens[1]
            value_partial = current_word if not ends_with_space else ""
            yield from self._iter_set_value_completions(option, value_partial)
            return

        if command == "proxy":
            args = tokens[1:]
            if ends_with_space:
                args.append("")
            yield from self._iter_proxy_completions(args, current_word, ends_with_space)
            return

        if command == "sessions":
            args = tokens[1:]
            if ends_with_space:
                args.append("")
            yield from self._iter_sessions_completions(args, current_word, ends_with_space)
            return

        # Generic subcommand support -----------------------------------------
        subcommands = self._get_subcommands(command)
        if subcommands:
            if (len(tokens) == 1 and ends_with_space) or (len(tokens) == 2 and not ends_with_space):
                partial = current_word if len(tokens) >= 2 and not ends_with_space else ""
                yield from self._iter_subcommand_completions(command, partial)
                return

        # Default fallback: when nothing matches, show command list
        if len(tokens) == 1:
            yield from self._iter_command_completions(current_word)
        else:
            # No additional hints, return empty iterator
            return

    # ------------------------------------------------------------------ #
    # Command completions
    # ------------------------------------------------------------------ #
    def _iter_command_completions(self, partial: str) -> Iterable[Completion]:
        for command in self._filter_items(self._get_available_commands(), partial, limit=25):
            yield Completion(command, start_position=-len(partial), display_meta="Command")

    def _iter_subcommand_completions(self, command: str, partial: str) -> Iterable[Completion]:
        for subcommand in self._filter_items(self._get_subcommands(command), partial):
            yield Completion(subcommand, start_position=-len(partial), display_meta="Subcommand")

    def _iter_module_completions(self, partial: str) -> Iterable[Completion]:
        for module_path in self._filter_items(self._get_modules(), partial, limit=40):
            yield Completion(module_path, start_position=-len(partial), display_meta="Module")

    def _iter_set_option_completions(self, partial: str) -> Iterable[Completion]:
        options = []
        if self.framework.current_module:
            # Get options from exploit_attributes (the actual option names)
            module_options = self.framework.current_module.get_options()
            if module_options:
                options = list(module_options.keys())
        # Keep original case, don't convert to uppercase
        for option in self._filter_items(sorted(set(options)), partial):
            yield Completion(option, start_position=-len(partial), display_meta="Option")

    def _iter_set_value_completions(self, option: str, partial: str) -> Iterable[Completion]:
        option_lower = option.lower()
        suggestions: List[str] = []

        if option_lower in ("session", "session_id", "target_session"):
            suggestions = self._collect_session_identifiers()
        elif option_lower in ("lhost", "rhost"):
            suggestions = self._local_ip_candidates()
        elif option_lower == "payload":
            suggestions = self._collect_payload_paths()

        if not suggestions:
            return

        for value in self._filter_items(suggestions, partial):
            yield Completion(value, start_position=-len(partial), display_meta="Payload")

    def _iter_proxy_completions(self, args: List[str], partial: str, ends_with_space: bool) -> Iterable[Completion]:
        subcommands = ['start', 'stop', 'status', 'list', 'show', 'replay', 'export', 'clear', 'hexdump']

        if not args or (len(args) == 1 and not ends_with_space and len(args[0]) == len(partial)):
            for item in self._filter_items(subcommands, partial):
                yield Completion(item, start_position=-len(partial), display_meta="Proxy Subcommand")
            return

        subcommand = args[0]

        if len(args) == 1 and ends_with_space:
            for opt in ['--host', '--port', '--mode', '--verbose']:
                yield Completion(opt, start_position=0, display_meta="Option")
            return

        # Handle specific subcommand options
        if subcommand == 'start':
            if partial.startswith('--'):
                for opt in self._filter_items(['--host', '--port', '--mode', '--verbose'], partial):
                    yield Completion(opt, start_position=-len(partial), display_meta="Option")
                return
            if len(args) >= 2 and args[-2] == '--mode':
                for value in self._filter_items(['http', 'socks'], partial):
                    yield Completion(value, start_position=-len(partial), display_meta="Mode")
                return

        if subcommand == 'list':
            if partial.startswith('--'):
                for opt in self._filter_items(['--limit', '--protocol', '--method'], partial):
                    yield Completion(opt, start_position=-len(partial), display_meta="Option")
                return
            if len(args) >= 2 and args[-2] == '--protocol':
                for proto in self._filter_items(['HTTP', 'HTTPS', 'TCP', 'UDP', 'SOCKS5'], partial.upper()):
                    yield Completion(proto, start_position=-len(partial), display_meta="Protocol")
                return

        if subcommand in ('show', 'replay', 'hexdump'):
            # Provide a generic request id prefix
            if len(args) == 2 and not ends_with_space:
                yield Completion('req_', start_position=-len(partial), display_meta="Request ID")
            return

    def _iter_sessions_completions(self, args: List[str], partial: str, ends_with_space: bool) -> Iterable[Completion]:
        """Handle completions for the sessions command"""
        subcommands = ['list', 'access', 'interact', 'kill', 'help']

        # Filter out empty strings from args (added when ends_with_space is True)
        args = [arg for arg in args if arg]

        # If no subcommand yet, or typing the subcommand
        if not args or (len(args) == 1 and not ends_with_space):
            for item in self._filter_items(subcommands, partial):
                yield Completion(item, start_position=-len(partial), display_meta="Sessions Subcommand")
            return

        subcommand = args[0].lower()

        # Subcommands that require a session_id
        if subcommand in ['interact', 'access', 'kill']:
            # If we're after the subcommand and need a session_id
            if len(args) == 1 and ends_with_space:
                # After subcommand with space, suggest session IDs
                session_ids = self._collect_session_identifiers()
                for session_id in self._filter_items(session_ids, ""):
                    yield Completion(session_id, start_position=0, display_meta="Session ID")
                return
            elif len(args) == 2:
                # Typing or after the session_id
                if not ends_with_space:
                    # Typing the session_id
                    session_ids = self._collect_session_identifiers()
                    for session_id in self._filter_items(session_ids, partial):
                        yield Completion(session_id, start_position=-len(partial), display_meta="Session ID")
                elif subcommand == 'kill' and args[1].lower() != 'all':
                    # After session_id with space (for kill, we might have "all")
                    yield Completion('all', start_position=0, display_meta="Kill all sessions")
                return

        # For 'kill all', no further completions needed
        if subcommand == 'kill' and len(args) >= 2 and args[1].lower() == 'all':
            return

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _get_available_commands(self) -> List[str]:
        now = time.time()
        if not self._command_cache or now - self._last_command_cache > self.CACHE_TTL:
            try:
                commands = self.command_registry.get_available_commands()
            except Exception:
                commands = list(self.command_registry.commands.keys())
            self._command_cache = sorted(set(commands))
            self._last_command_cache = now
        return self._command_cache

    def _get_modules(self) -> List[str]:
        now = time.time()
        if not self._modules_cache or now - self._last_module_cache > self.CACHE_TTL:
            try:
                discovered = self.framework.module_loader.discover_modules()
                module_paths = sorted(discovered.keys())
            except Exception:
                module_paths = []
            self._modules_cache = module_paths
            self._last_module_cache = now
        return self._modules_cache

    def _get_subcommands(self, command: str) -> List[str]:
        if command not in self._subcommand_cache:
            subcommands: List[str] = []
            cmd_instance = self.command_registry.commands.get(command)
            if not cmd_instance:
                try:
                    cmd_instance = self.command_registry.get_command(command)
                except Exception:
                    cmd_instance = None
            if cmd_instance and hasattr(cmd_instance, 'get_subcommands'):
                try:
                    subcommands = list(cmd_instance.get_subcommands() or [])
                except Exception:
                    subcommands = []
            self._subcommand_cache[command] = sorted(set(subcommands))
        return self._subcommand_cache.get(command, [])

    def _filter_items(self, items: Iterable[str], partial: str, limit: Optional[int] = None) -> List[str]:
        items = list(dict.fromkeys(items))  # Remove duplicates while preserving order
        if not partial:
            results = items
        else:
            lower = partial.lower()
            prefix_matches = [item for item in items if item.lower().startswith(lower)]
            remaining = [item for item in items if item not in prefix_matches]
            fuzzy = difflib.get_close_matches(partial, remaining, n=limit or 15, cutoff=0.6)
            results = prefix_matches + [item for item in remaining if item in fuzzy]
        if limit:
            results = list(islice(results, limit))
        return results

    def _collect_session_identifiers(self) -> List[str]:
        identifiers: List[str] = []
        session_manager = getattr(self.framework, 'session_manager', None)
        if not session_manager:
            return identifiers

        try:
            for session in session_manager.get_sessions():
                if getattr(session, 'id', None):
                    identifiers.append(session.id)
        except Exception:
            pass

        try:
            for session in session_manager.get_browser_sessions():
                session_id = session.get('id')
                if session_id:
                    identifiers.append(session_id)
        except Exception:
            pass

        return sorted(set(filter(None, identifiers)))

    def _local_ip_candidates(self) -> List[str]:
        candidates = {'127.0.0.1'}
        try:
            hostname = socket.gethostname()
            _, _, addresses = socket.gethostbyname_ex(hostname)
            candidates.update(addresses)
        except OSError:
            pass
        return sorted(set(filter(None, candidates)))

    def _collect_payload_paths(self) -> List[str]:
        """Collect all available payload module paths"""
        payload_paths: List[str] = []
        
        try:
            if not hasattr(self.framework, 'module_loader'):
                return payload_paths
            
            # Discover all modules
            discovered_modules = self.framework.module_loader.discover_modules()
            
            # Filter payload modules (they start with "payloads/")
            for module_path in discovered_modules.keys():
                if module_path.startswith("payloads/"):
                    payload_paths.append(module_path)
        except Exception:
            pass
        
        return sorted(set(filter(None, payload_paths)))


class ContextFilter(Filter):
    """Filter to determine when to show completions."""

    def __init__(self, completer: AdvancedCompleter):
        self.completer = completer

    def __call__(self) -> bool:
        return True
