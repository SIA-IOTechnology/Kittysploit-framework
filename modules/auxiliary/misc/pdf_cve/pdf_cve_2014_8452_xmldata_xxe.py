#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.javascript import write_js_xxe_xmldata


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2014-8452 XMLData XXE Callback',
        "description": 'Generate PDF PoC for CVE-2014-8452: Acrobat JavaScript XMLData.parse() external entity resolution phone-home.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2014-8452'],
        "references": ['https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html'],
        "tags": ['pdf', 'cve-2014-8452', 'xxe', 'javascript', 'acrobat'],
    }

    PDF_GENERATORS = (
        write_js_xxe_xmldata,
    )

    CVE_IDS = ['CVE-2014-8452']
    MODULE_TITLE = 'PDF CVE-2014-8452 XMLData XXE Callback'

    def run(self):
        return self.run_pdf_cve()