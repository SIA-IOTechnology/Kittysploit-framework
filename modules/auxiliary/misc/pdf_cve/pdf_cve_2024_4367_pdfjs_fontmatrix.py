#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.viewer_cve import write_pdfjs_fontmatrix


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2024-4367 PDF.js FontMatrix RCE PoC',
        "description": 'Generate PDF PoC for CVE-2024-4367: arbitrary JavaScript via unsanitized Type1 FontMatrix in PDF.js (fetch callback for validation).',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2024-4367'],
        "references": ['https://codeanlabs.com/2024/05/cve-2024-4367-arbitrary-js-execution-in-pdf-js/'],
        "tags": ['pdf', 'cve-2024-4367', 'pdfjs', 'firefox', 'javascript'],
    }

    PDF_GENERATORS = (
        write_pdfjs_fontmatrix,
    )

    CVE_IDS = ['CVE-2024-4367']
    MODULE_TITLE = 'PDF CVE-2024-4367 PDF.js FontMatrix RCE PoC'

    def run(self):
        return self.run_pdf_cve()