#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Search command implementation
"""

from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_table, print_empty


def _one_line(s: str) -> str:
    return " ".join(str(s or "").split())


class SearchCommand(BaseCommand):
    """Command to search for modules"""
    
    @property
    def name(self) -> str:
        return "search"
    
    @property
    def description(self) -> str:
        return "Search for modules by keyword"
    
    @property
    def usage(self) -> str:
        return "search <keyword>"
    
    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

When the workspace module index (database) is available, search uses SQL
only — no filesystem scan, no imports. Each keyword must appear in at least
one of: title, description, module path, or tags (stored JSON). Several words
are combined with AND.

If the framework runs without a DB index, search falls back to a static
parse of ``__info__`` from ``.py`` files (still no imports).

After adding or changing modules, run ``sync`` / ``sync now`` so the index
stays up to date.

Examples:
    search wordpress            # path or metadata mentions wordpress
    search scanner              # keyword in indexed fields
    search http sql             # both tokens must match (any field each)
    search auxiliary            # path/type text as indexed
        """
    
    def execute(self, args, **kwargs) -> bool:
        """Execute the search command"""
        if len(args) == 0:
            print_error("Usage: search <keyword> [more keywords...]")
            return False

        display_query = " ".join(args).strip()
        keyword = display_query.lower()

        try:
            plugin_manager = getattr(self.framework, 'plugin_manager', None)
            metasploit_plugin = plugin_manager.get_plugin("metasploit") if plugin_manager else None
            msf_mode = bool(
                metasploit_plugin
                and getattr(metasploit_plugin, "is_integrated_mode_active", lambda: False)()
            )

            matches = self.framework.search_modules_db(query=keyword, limit=50)
            msf_output = ""
            if msf_mode:
                try:
                    msf_output = metasploit_plugin.msf_search(display_query)
                except Exception as exc:
                    print_error(f"Metasploit search error: {exc}")

            if not matches and not msf_output.strip():
                print_info(f"No modules found matching '{display_query}'")
                try:
                    sm = getattr(self.framework, "module_sync_manager", None)
                    if sm:
                        stats = sm.get_module_stats()
                        if isinstance(stats, dict) and stats.get("total", 0) == 0:
                            print_info(
                                "Module index is empty. Run 'sync now' (or 'sync') "
                                "to load modules into the database."
                            )
                except Exception:
                    pass
                return True

            if matches:
                print_success(f"KittySploit: found {len(matches)} module(s) matching '{display_query}'")
                print_empty()

                rows = []
                for module in sorted(matches, key=lambda m: (m.get("path") or "").lower()):
                    path = _one_line(module.get("path") or "")
                    mtype = _one_line(module.get("type") or "—")
                    title = _one_line(module.get("name") or "—")
                    desc = _one_line(module.get("description") or "")
                    rows.append([path, mtype, title, desc])

                print_table(
                    ["Path", "Type", "Name", "Description"],
                    rows,
                    max_width=100,
                    expand_to_terminal=True,
                    column_min_widths={"Path": 44, "Type": 14, "Name": 24},
                    protect_full_width_headers=(),
                    wrap_extra_headers=("name", "path"),
                )
                print_empty()
                print_info("KittySploit select with: use <Path>")

            if msf_mode:
                print_empty()
                print_info("=" * 100)
                print_info(f"Metasploit results for '{display_query}'")
                print_info("=" * 100)
                if msf_output.strip():
                    print(msf_output, end="" if msf_output.endswith("\n") else "\n")
                else:
                    print_info("No Metasploit modules found.")

            return True
            
        except Exception as e:
            print_error(f"Error searching modules: {str(e)}")
            return False
