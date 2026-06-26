#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Module inventory command — catalog coverage, duplicates, and gaps."""

from __future__ import annotations

import argparse
import json

from core.module_inventory import analyze_discovered_modules, export_inventory_json
from core.output_handler import (
    print_empty,
    print_error,
    print_info,
    print_success,
    print_table,
    print_warning,
)
from interfaces.command_system.base_command import BaseCommand


class InventoryCommand(BaseCommand):
    """Build an automatic inventory of local KittySploit modules."""

    @property
    def name(self) -> str:
        return "inventory"

    @property
    def description(self) -> str:
        return (
            "Analyze the local module catalog: metadata, duplicates, broken modules, "
            "empty categories, and coverage gaps"
        )

    @property
    def usage(self) -> str:
        return (
            "inventory [--json] [--verbose] [--export <file.json>] "
            "[--only summary|duplicates|broken|gaps|empty|potential|all] "
            "[--type <module_type>] [--protocol <protocol>]"
        )

    @property
    def help_text(self) -> str:
        return f"""
{self.description}

Usage: {self.usage}

Builds a static inventory from module sources (no import / no execution).
Each row includes type, protocol, platform, CVE, privileges, reliability,
required options, tags, dependencies, and ATT&CK technique hints.

Sections:
    summary      Counts by type, protocol, and platform
    duplicates   Same name, CVE, or basename across multiple paths
    broken       Modules failing the static contract (syntax, missing __info__, etc.)
    gaps         Under-covered protocols and missing module types
    empty        Supported module categories with zero modules
    potential    Scanner-heavy protocols without exploit modules

Options:
    --json              Machine-readable report on stdout
    --verbose, -v       List every indexed module
    --export <path>     Write the full JSON report to a file
    --only <section>    Show one section (default: summary + highlights)
    --type <type>       Filter by module type (exploits, scanner, payloads, ...)
    --protocol <name>   Filter by protocol facet (http, ssh, smb, ...)

Examples:
    inventory
    inventory --only duplicates
    inventory --type scanner --protocol http --verbose
    inventory --export /tmp/module_inventory.json
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="Analyze the local module inventory",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--json", action="store_true", help="JSON output")
        parser.add_argument("--verbose", "-v", action="store_true", help="List all modules")
        parser.add_argument("--export", metavar="FILE", help="Write JSON report to file")
        parser.add_argument(
            "--only",
            choices=["summary", "duplicates", "broken", "gaps", "empty", "potential", "all"],
            default="summary",
            help="Section to display (default: summary highlights)",
        )
        parser.add_argument("--type", dest="module_type", default="", help="Filter by module type")
        parser.add_argument("--protocol", default="", help="Filter by protocol facet")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        module_loader = getattr(self.framework, "module_loader", None)
        if module_loader is None:
            print_error("Module loader is not available")
            return False

        discovered = module_loader.discover_modules()
        analysis = analyze_discovered_modules(
            discovered,
            module_type=parsed.module_type,
            protocol=parsed.protocol,
        )

        if parsed.export:
            try:
                export_inventory_json(analysis, parsed.export)
                print_success(f"Inventory exported to {parsed.export}")
            except OSError as exc:
                print_error(f"Could not write inventory export: {exc}")
                return False

        if parsed.json:
            print_info(json.dumps(analysis.to_dict(), indent=2, sort_keys=True))
            return True

        if parsed.only == "all":
            self._print_summary(analysis)
            print_empty()
            self._print_duplicates(analysis)
            print_empty()
            self._print_broken(analysis)
            print_empty()
            self._print_gaps(analysis)
            print_empty()
            self._print_empty_categories(analysis)
            print_empty()
            self._print_potential(analysis)
        elif parsed.only == "duplicates":
            self._print_duplicates(analysis)
        elif parsed.only == "broken":
            self._print_broken(analysis)
        elif parsed.only == "gaps":
            self._print_gaps(analysis)
        elif parsed.only == "empty":
            self._print_empty_categories(analysis)
        elif parsed.only == "potential":
            self._print_potential(analysis)
        else:
            self._print_summary(analysis)
            if analysis.duplicates_by_name or analysis.duplicates_by_cve:
                print_empty()
                self._print_duplicates(analysis, limit=5)
            if analysis.broken_modules:
                print_empty()
                self._print_broken(analysis, limit=10)
            if analysis.high_potential_areas:
                print_empty()
                self._print_potential(analysis, limit=5)

        if parsed.verbose:
            print_empty()
            self._print_module_table(analysis)

        return True

    def _print_summary(self, analysis) -> None:
        print_info("Module Inventory Summary")
        print_info("=" * 50)
        print_info(f"Total modules indexed: {analysis.total}")
        print_info(f"Broken modules: {len(analysis.broken_modules)}")
        print_info(f"Incomplete metadata: {len(analysis.incomplete_modules)}")
        print_info(f"Duplicate names: {len(analysis.duplicates_by_name)}")
        print_info(f"Duplicate CVEs: {len(analysis.duplicates_by_cve)}")
        print_info(f"Empty categories: {len(analysis.empty_categories)}")
        print_info(f"Coverage gaps: {len(analysis.coverage_gaps)}")
        print_info(f"ATT&CK techniques referenced: {len(analysis.attack_technique_coverage)}")

        print_empty()
        print_info("By type:")
        for module_type, count in analysis.by_type.items():
            print_info(f"  {module_type}: {count}")

        if analysis.by_protocol:
            print_empty()
            print_info("Top protocols:")
            for protocol, count in list(analysis.by_protocol.items())[:12]:
                print_info(f"  {protocol}: {count}")

    def _print_duplicates(self, analysis, *, limit: int = 0) -> None:
        print_info("Duplicate groups")
        print_info("-" * 50)
        sections = (
            ("name", analysis.duplicates_by_name),
            ("cve", analysis.duplicates_by_cve),
            ("basename", analysis.duplicates_by_basename),
        )
        shown = 0
        for label, groups in sections:
            if not groups:
                continue
            for key, paths in sorted(groups.items()):
                print_warning(f"[{label}] {key}")
                for path in paths:
                    print_info(f"  {path}")
                shown += 1
                if limit and shown >= limit:
                    return

    def _print_broken(self, analysis, *, limit: int = 0) -> None:
        print_info("Broken modules (static contract errors)")
        print_info("-" * 50)
        if not analysis.broken_modules:
            print_success("No broken modules detected")
            return
        for index, path in enumerate(analysis.broken_modules, start=1):
            entry = next(item for item in analysis.entries if item.path == path)
            print_error(path)
            for error in entry.errors[:3]:
                print_info(f"  - {error}")
            if limit and index >= limit:
                remaining = len(analysis.broken_modules) - limit
                if remaining > 0:
                    print_info(f"  ... and {remaining} more")
                break

    def _print_gaps(self, analysis) -> None:
        print_info("Coverage gaps")
        print_info("-" * 50)
        if not analysis.coverage_gaps:
            print_success("No major coverage gaps detected")
            return
        for gap in analysis.coverage_gaps:
            print_warning(gap.get("message") or str(gap))

    def _print_empty_categories(self, analysis) -> None:
        print_info("Empty module categories")
        print_info("-" * 50)
        if not analysis.empty_categories:
            print_success("All supported module categories have at least one module")
            return
        for category in analysis.empty_categories:
            print_warning(category)

    def _print_potential(self, analysis, *, limit: int = 0) -> None:
        print_info("High-potential areas")
        print_info("-" * 50)
        if not analysis.high_potential_areas:
            print_info("No scanner/exploit imbalance detected for indexed protocols")
            return
        for index, area in enumerate(analysis.high_potential_areas, start=1):
            print_success(area.get("message") or str(area))
            if limit and index >= limit:
                remaining = len(analysis.high_potential_areas) - limit
                if remaining > 0:
                    print_info(f"... and {remaining} more")
                break

    def _print_module_table(self, analysis) -> None:
        rows = []
        for entry in analysis.entries:
            rows.append(
                [
                    entry.path,
                    entry.module_type,
                    entry.protocol or "-",
                    entry.platform or "-",
                    entry.cve or "-",
                    ", ".join(entry.required_options[:3]) or "-",
                    ", ".join(entry.attack_techniques[:2]) or "-",
                    "ok" if entry.valid else "broken",
                ]
            )
        print_table(
            [
                "Path",
                "Type",
                "Protocol",
                "Platform",
                "CVE",
                "Required opts",
                "ATT&CK",
                "Status",
            ],
            rows,
        )
