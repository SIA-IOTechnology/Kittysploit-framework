#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.xxe import write_foxit_xxe_callback


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": "PDF CVE-2026-57259 Foxit XXE Callback",
        "description": (
            "Generate PDF PoC for CVE-2026-57259: Foxit XML/XXE phone-home via XMP "
            "parameter entity (lab callback URL). For authorized parser/viewer regression."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-57259"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-57259"],
        "tags": ["pdf", "cve-2026-57259", "xxe", "foxit", "xmp"],
    }

    PDF_GENERATORS = (write_foxit_xxe_callback,)
    CVE_IDS = ["CVE-2026-57259"]
    MODULE_TITLE = "PDF CVE-2026-57259 Foxit XXE Callback"

    def run(self):
        return self.run_pdf_cve()
