#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Doctor command — framework health diagnostics."""

from __future__ import annotations

import argparse
import json
from typing import List

from colorama import Fore, Style

from core.doctor import ALL_CATEGORIES, CheckStatus, Doctor
from core.output_handler import print_error, print_info, print_success, print_table, print_warning
from interfaces.command_system.base_command import BaseCommand

_STATUS_STYLE = {
    CheckStatus.OK: (print_success, Fore.GREEN),
    CheckStatus.WARN: (print_warning, Fore.YELLOW),
    CheckStatus.FAIL: (print_error, Fore.RED),
}


class DoctorCommand(BaseCommand):
    """Run environment and framework health checks."""

    @property
    def name(self) -> str:
        return "doctor"

    @property
    def description(self) -> str:
        return "Diagnose Python, dependencies, Zig, Docker, Tor, database, assets, permissions, wordlists and marketplace"

    @property
    def usage(self) -> str:
        return "doctor [--only <categories>] [--json] [--verbose]"

    @property
    def help_text(self) -> str:
        categories = ", ".join(ALL_CATEGORIES)
        return f"""
{self.description}

Usage: {self.usage}

Runs a non-destructive health check of the local KittySploit environment.

Categories:
    {categories}

Options:
    --only <list>   Comma-separated categories to run (default: all)
    --json          Output machine-readable JSON report
    --verbose, -v   Show hints for warnings and failures

Examples:
    doctor
    doctor --only python,dependencies,db
    doctor --json
        """

    def get_subcommands(self) -> List[str]:
        return list(ALL_CATEGORIES)

    def __init__(self, framework=None, session=None, output_handler=None):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="doctor",
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            "--only",
            metavar="CATEGORIES",
            help=f"Comma-separated checks: {', '.join(ALL_CATEGORIES)}",
        )
        parser.add_argument("--json", action="store_true", help="Print JSON report")
        parser.add_argument("--verbose", "-v", action="store_true", help="Show remediation hints")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        categories = None
        if parsed.only:
            categories = [part.strip().lower() for part in parsed.only.split(",") if part.strip()]
            unknown = [c for c in categories if c not in ALL_CATEGORIES]
            if unknown:
                print_error(f"Unknown categories: {', '.join(unknown)}")
                print_info(f"Valid categories: {', '.join(ALL_CATEGORIES)}")
                return False

        report = Doctor(self.framework).run(categories)

        if parsed.json:
            print(json.dumps(report.to_dict(), indent=2))
            return report.healthy

        self._print_report(report, verbose=parsed.verbose)
        return report.healthy

    def _print_report(self, report, verbose: bool = False) -> None:
        rows = []
        for result in report.results:
            status = result.status.value.upper()
            rows.append([result.category, result.name, status, result.detail])

        print_info("KittySploit doctor")
        print_table(
            ["Category", "Check", "Status", "Description"],
            rows,
            column_min_widths={"Category": 12, "Check": 18, "Status": 6},
            prefer_single_line=True,
        )

        counts = report.counts
        summary = (
            f"{Fore.GREEN}{counts['ok']} ok{Style.RESET_ALL}, "
            f"{Fore.YELLOW}{counts['warn']} warn{Style.RESET_ALL}, "
            f"{Fore.RED}{counts['fail']} fail{Style.RESET_ALL}"
        )
        print_info(f"Summary: {summary}")

        if verbose:
            hints = [r for r in report.results if r.hint and r.status != CheckStatus.OK]
            if hints:
                print_info("Hints:")
                for result in hints:
                    printer, color = _STATUS_STYLE[result.status]
                    print(f"  {color}• {result.category}/{result.name}:{Style.RESET_ALL} {result.hint}")

        if report.healthy:
            print_success("All critical checks passed.")
        else:
            print_error("One or more critical checks failed. Re-run with --verbose for hints.")
