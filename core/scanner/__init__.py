#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deduplicate and group KittySploit scanner findings."""

from core.scanner.result_dedup import (
    ScannerFindingGroup,
    deduplicate_scanner_results,
    enrich_scanner_result,
    group_scanner_results,
)

__all__ = [
    "ScannerFindingGroup",
    "deduplicate_scanner_results",
    "enrich_scanner_result",
    "group_scanner_results",
]
