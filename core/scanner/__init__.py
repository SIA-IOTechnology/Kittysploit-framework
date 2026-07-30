#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Deduplicate and group KittySploit scanner findings."""

from core.scanner.result_dedup import (
    ScannerFindingGroup,
    deduplicate_scanner_results,
    enrich_scanner_result,
    group_scanner_results,
)
from core.scanner.evidence_capture import (
    collect_module_evidence,
    evidence_dir_for_scan,
    evidence_preview,
    write_evidence_records,
)
from core.scanner.finding_report import (
    build_finding_report,
    extract_finding_report,
    report_to_vulnerability_fields,
    vulnerability_to_kittyreport_finding,
)
from core.scanner.screenshot import (
    attach_screenshots_to_results,
    capture_page_screenshot,
    playwright_available,
)

__all__ = [
    "ScannerFindingGroup",
    "deduplicate_scanner_results",
    "enrich_scanner_result",
    "group_scanner_results",
    "collect_module_evidence",
    "evidence_dir_for_scan",
    "evidence_preview",
    "write_evidence_records",
    "build_finding_report",
    "extract_finding_report",
    "report_to_vulnerability_fields",
    "vulnerability_to_kittyreport_finding",
    "attach_screenshots_to_results",
    "capture_page_screenshot",
    "playwright_available",
]
