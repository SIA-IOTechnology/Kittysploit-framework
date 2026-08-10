# -*- coding: utf-8 -*-
"""Masscan wrapper: run CLI and parse JSON into workspace-friendly structures."""

from lib.scanner.masscan.parse import parse_masscan_json, to_port_scan_results
from lib.scanner.masscan.runner import masscan_available, resolve_masscan_cli, run_masscan

__all__ = [
    "masscan_available",
    "parse_masscan_json",
    "resolve_masscan_cli",
    "run_masscan",
    "to_port_scan_results",
]
