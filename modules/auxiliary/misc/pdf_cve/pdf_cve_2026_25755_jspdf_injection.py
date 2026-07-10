#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.viewer_cve import write_jspdf_object_injection


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2026-25755 jsPDF Object Injection',
        "description": 'Generate PDF PoC for CVE-2026-25755: jsPDF addJS() object injection with /AA /O auto-action URI callback.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2026-25755'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2026-25755'],
        "tags": ['pdf', 'cve-2026-25755', 'jspdf', 'injection'],
    }

    PDF_GENERATORS = (
        write_jspdf_object_injection,
    )

    CVE_IDS = ['CVE-2026-25755']
    MODULE_TITLE = 'PDF CVE-2026-25755 jsPDF Object Injection'

    def run(self):
        return self.run_pdf_cve()