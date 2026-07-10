#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Search command implementation."""

import argparse

from core.module_search import ModuleSearchFilters, parse_date
from interfaces.command_system.base_command import BaseCommand
from core.output_handler import print_info, print_success, print_error, print_table, print_empty


def _one_line(s: str) -> str:
    return " ".join(str(s or "").split())


class SearchCommand(BaseCommand):
    """Command to search for modules with structured filters."""

    @property
    def name(self) -> str:
        return "search"

    @property
    def description(self) -> str:
        return "Search modules by keyword and filters (CVE, tags, platform, protocol, reliability, type, author, date)"

    @property
    def usage(self) -> str:
        return (
            "search [keywords...] [--type TYPE] [--cve CVE] [--tag TAG] [--platform PLATFORM] "
            "[--protocol PROTO] [--reliability LEVEL] [--author AUTHOR] [--since DATE] [--until DATE] [--limit N]"
        )

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

When the workspace module index (database) is available, search uses SQL
with optional structured filters. Each keyword must appear in at least one of:
title, description, module path, tags, author, or CVE.

If the framework runs without a DB index, search falls back to a static
parse of ``__info__`` from ``.py`` files (still no imports).

After adding or changing modules, run ``sync`` / ``sync now`` so the index
stays up to date.

Filters:
    --type, -t          Module type (scanner, exploits, auxiliary, payloads, ...)
    --cve               CVE identifier (partial match)
    --tag               Tag (partial match in stored tags JSON)
    --platform          Platform (linux, unix, windows, php, multi, ...)
    --protocol          Protocol/service family (http, ldap, smb, ssh, ...)
    --reliability       Reliability/severity bucket (high, medium, low)
    --author            Author name (partial match)
    --since DATE        Updated on/after DATE (YYYY-MM-DD)
    --until DATE        Updated on/before DATE (YYYY-MM-DD)
    --limit N           Maximum results (default: 50)

Examples:
    search wordpress
    search --type scanner --protocol http
    search --cve CVE-2026-24849
    search --tag authenticated --reliability high
    search --platform linux --type exploits
    search --author "KittySploit Team" --since 2025-01-01
    search sql injection --type auxiliary --protocol http
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(prog="search", description=self.description, add_help=False)
        parser.add_argument("keywords", nargs="*", help="Free-text keywords (AND)")
        parser.add_argument("--type", "-t", dest="module_type", help="Module type filter")
        parser.add_argument("--cve", help="CVE filter")
        parser.add_argument("--tag", help="Tag filter")
        parser.add_argument("--platform", help="Platform filter")
        parser.add_argument("--protocol", help="Protocol filter")
        parser.add_argument("--reliability", help="Reliability/severity filter")
        parser.add_argument("--author", help="Author filter")
        parser.add_argument("--since", help="Updated since YYYY-MM-DD")
        parser.add_argument("--until", help="Updated until YYYY-MM-DD")
        parser.add_argument("--limit", type=int, default=50, help="Maximum results")
        return parser

    def execute(self, args, **kwargs) -> bool:
        if not args:
            print_info(self.help_text)
            return True

        if args[0].lower() in {"-h", "--help", "help"}:
            print_info(self.help_text)
            return True

        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        if not parsed.keywords and not any(
            [
                parsed.module_type,
                parsed.cve,
                parsed.tag,
                parsed.platform,
                parsed.protocol,
                parsed.reliability,
                parsed.author,
                parsed.since,
                parsed.until,
            ]
        ):
            print_error("Provide keywords and/or at least one filter.")
            print_info(f"Usage: {self.usage}")
            return False

        filters = ModuleSearchFilters(
            query=" ".join(parsed.keywords).strip().lower(),
            module_type=parsed.module_type or "",
            author=parsed.author or "",
            cve=parsed.cve or "",
            tag=parsed.tag or "",
            platform=parsed.platform or "",
            protocol=parsed.protocol or "",
            reliability=parsed.reliability or "",
            since=parse_date(parsed.since) if parsed.since else None,
            until=parse_date(parsed.until) if parsed.until else None,
            limit=max(1, int(parsed.limit or 50)),
        )

        display_query = filters.summary()

        try:
            plugin_manager = getattr(self.framework, "plugin_manager", None)
            metasploit_plugin = plugin_manager.get_plugin("metasploit") if plugin_manager else None
            msf_mode = bool(
                metasploit_plugin
                and getattr(metasploit_plugin, "is_integrated_mode_active", lambda: False)()
            )

            matches = self.framework.search_modules_db(filters=filters)
            msf_output = ""
            if msf_mode and filters.query:
                try:
                    msf_output = metasploit_plugin.msf_search(filters.query)
                except Exception as exc:
                    print_error(f"Metasploit search error: {exc}")

            if not matches and not msf_output.strip():
                print_info(f"No modules found matching {display_query}")
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
                print_success(f"KittySploit: found {len(matches)} module(s) matching {display_query}")
                print_empty()

                rows = []
                for module in sorted(matches, key=lambda m: (m.get("path") or "").lower()):
                    path = _one_line(module.get("path") or "")
                    mtype = _one_line(module.get("type") or "—")
                    cve = _one_line(module.get("cve") or "—")
                    protocol = _one_line(module.get("protocol") or "—")
                    reliability = _one_line(module.get("reliability") or "—")
                    updated = _one_line((module.get("updated_at") or "")[:10] or "—")
                    desc = _one_line(module.get("description") or "")
                    rows.append([path, mtype, cve, protocol, reliability, updated, desc])

                print_table(
                    ["Path", "Type", "CVE", "Proto", "Rel.", "Updated", "Description"],
                    rows,
                    max_width=120,
                    expand_to_terminal=True,
                    column_min_widths={
                        "Path": 36,
                        "Type": 10,
                        "CVE": 15,
                        "Updated": 10,
                        "Description": 24,
                    },
                    protect_full_width_headers=(),
                    wrap_extra_headers=("path", "description"),
                )
                print_empty()
                print_info("KittySploit select with: use <Path>")

            if msf_mode:
                print_empty()
                print_info("=" * 100)
                print_info(f"Metasploit results for '{filters.query}'")
                print_info("=" * 100)
                if msf_output.strip():
                    print(msf_output, end="" if msf_output.endswith("\n") else "\n")
                else:
                    print_info("No Metasploit modules found.")

            return True

        except Exception as e:
            print_error(f"Error searching modules: {str(e)}")
            return False

    def get_subcommands(self):
        return [
            "--type",
            "-t",
            "--cve",
            "--tag",
            "--platform",
            "--protocol",
            "--reliability",
            "--author",
            "--since",
            "--until",
            "--limit",
        ]
