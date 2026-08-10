# -*- coding: utf-8 -*-
"""Nmap wrapper: run CLI and parse XML into workspace-friendly structures."""

from lib.scanner.nmap.parse import parse_nmap_xml
from lib.scanner.nmap.runner import nmap_available, resolve_nmap_cli, run_nmap

__all__ = [
    "nmap_available",
    "parse_nmap_xml",
    "resolve_nmap_cli",
    "run_nmap",
]
