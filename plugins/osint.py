#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OSINT Plugin for KittySploit
Run all OSINT auxiliary modules against a target from kittyconsole.
"""

import shlex
import socket
import ipaddress
from typing import List

from kittysploit import *


class OsintPlugin(Plugin):
    """Run OSINT modules in batch from kittyconsole."""

    __info__ = {
        "name": "osint",
        "description": "Run all OSINT modules on a target from command line",
        "version": "1.0.0",
        "author": "KittySploit Team",
        "dependencies": [],
    }

    def __init__(self, framework=None):
        super().__init__(framework)

    def _safe_text(self, value) -> str:
        # Avoid malformed token errors in console renderers expecting XML-like markup.
        return (
            str(value)
            .replace("&", "and")
            .replace("<", "(")
            .replace(">", ")")
        )

    def _load_osint_tool(self):
        previous_module = getattr(self.framework, "current_module", None) if self.framework else None
        try:
            from interfaces.kittyosint.core import KittyOSINT
            return KittyOSINT(framework=self.framework)
        except Exception as e:
            print_error(f"Failed to initialize KittyOSINT core: {e}")
            return None
        finally:
            # Avoid changing the interactive prompt context while just discovering OSINT modules.
            if self.framework is not None:
                self.framework.current_module = previous_module

    def _print_modules(self, tool):
        modules = list(tool.modules.items())
        if not modules:
            print_warning("No OSINT modules found.")
            return

        rows = []
        for module_id, module_obj in modules:
            info = tool._module_info(module_obj)
            rows.append([
                module_id,
                str(info.get("Name") or module_id),
                str(info.get("Type") or "core"),
            ])

        print_info("Available OSINT modules:")
        print_info("------------------------------------------------------------")
        for row in rows:
            module_id = self._safe_text(row[0])
            name = self._safe_text(row[1])
            mtype = self._safe_text(row[2])
            print_info(f"- {module_id} | {name} | {mtype}")
        print_info("------------------------------------------------------------")
        print_info(f"Total OSINT modules: {len(rows)}")

    def _extract_target_from_tokens(self, tokens: List[str]) -> str:
        # Fallback for: plugin run osint <target>
        if not tokens:
            return ""
        for token in tokens:
            if not token.startswith("-"):
                return token.strip()
        return ""

    def _is_ipv4(self, value: str) -> bool:
        try:
            ipaddress.IPv4Address((value or "").strip())
            return True
        except Exception:
            return False

    def _resolve_ipv4_for_target(self, target: str) -> str:
        t = (target or "").strip()
        if not t:
            return ""
        if self._is_ipv4(t):
            return t
        try:
            # Resolve first IPv4 from host.
            _host, _aliases, addrs = socket.gethostbyname_ex(t)
            if addrs:
                return str(addrs[0]).strip()
        except Exception:
            return ""
        return ""

    def run(self, *args, **kwargs):
        parser = ModuleArgumentParser(description=self.__doc__, prog="osint")
        parser.add_argument("-t", "--target", dest="target", help="Target domain/ip/email", type=str)
        parser.add_argument("-l", "--list", dest="list_only", action="store_true", help="List available OSINT modules")
        parser.add_argument("-m", "--module", dest="module_id", help="Run a single OSINT module by id", type=str)
        parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Verbose module output")

        if not args or not args[0]:
            parser.print_help()
            return True

        try:
            raw_args = args[0] if isinstance(args[0], str) else " ".join(args)
            tokens = shlex.split(raw_args)
            pargs = parser.parse_args(tokens)

            if getattr(pargs, "help", False):
                parser.print_help()
                return True

            tool = self._load_osint_tool()
            if tool is None:
                return False

            if pargs.list_only:
                self._print_modules(tool)
                # If only list is requested, stop here.
                if not getattr(pargs, "target", None):
                    return True

            target = (pargs.target or "").strip()
            if not target:
                target = self._extract_target_from_tokens(tokens)

            if not target:
                print_error("Target is required. Use: plugin run osint -t <target>")
                return False

            if getattr(pargs, "module_id", None):
                module_id = str(pargs.module_id).strip()
                if module_id not in tool.modules:
                    print_error(f"Unknown OSINT module: {module_id}")
                    print_info("Use 'plugin run osint -l' to list available module ids.")
                    return False
                module_ids = [module_id]
            else:
                module_ids = list(tool.modules.keys())

            if not module_ids:
                print_warning("No OSINT modules available to run.")
                return True

            print_success(f"Running {len(module_ids)} OSINT module(s) on target: {target}")

            ok_count = 0
            fail_count = 0
            skip_count = 0
            resolved_ipv4 = self._resolve_ipv4_for_target(target)
            if resolved_ipv4 and resolved_ipv4 != target:
                print_info(f"[OSINT] Resolved IPv4 for IP modules: {target} -> {resolved_ipv4}")

            for module_id in module_ids:
                module_target = target
                if module_id.startswith("ip_"):
                    if resolved_ipv4:
                        module_target = resolved_ipv4
                    else:
                        print_warning(f"[{module_id}] skipped: unable to resolve IPv4 from target '{target}'")
                        skip_count += 1
                        continue

                print_info(f"[OSINT] Running: {module_id} on {module_target}")
                result = tool.execute_module(module_id, module_target)

                if isinstance(result, dict) and result.get("error"):
                    fail_count += 1
                    print_error(f"[{module_id}] {result.get('error')}")
                    continue

                raw = result.get("raw", {}) if isinstance(result, dict) else {}
                if isinstance(raw, dict) and raw.get("skipped"):
                    skip_count += 1
                    reason = raw.get("reason", "skipped")
                    print_warning(f"[{module_id}] skipped: {reason}")
                    if getattr(pargs, "verbose", False):
                        for key, value in raw.items():
                            print_info(f"  - {self._safe_text(key)}: {self._safe_text(value)}")
                    continue

                ok_count += 1
                graph = result.get("graph", {}) if isinstance(result, dict) else {}
                node_count = len(graph.get("nodes", []) or [])
                edge_count = len(graph.get("edges", []) or [])
                print_success(f"[{module_id}] completed (nodes: {node_count}, edges: {edge_count})")

                if getattr(pargs, "verbose", False):
                    if isinstance(raw, dict) and raw:
                        for key, value in raw.items():
                            print_info(f"  - {self._safe_text(key)}: {self._safe_text(value)}")

            print_info("")
            print_success(f"OSINT batch complete. Success: {ok_count} | Failed: {fail_count} | Skipped: {skip_count}")
            return True

        except Exception as e:
            print_error(f"OSINT plugin error: {e}")
            if is_debug_mode():
                import traceback
                traceback.print_exc()
            return False
