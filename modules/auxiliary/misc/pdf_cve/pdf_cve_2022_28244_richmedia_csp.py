#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.viewer_cve import write_richmedia_csp_bypass


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2022-28244 RichMedia CSP Bypass',
        "description": 'Generate PDF PoC for CVE-2022-28244: RichMedia annotation with embedded HTML/JS bypassing Acrobat CSP for outbound callback.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2022-28244'],
        "references": ['https://helpx.adobe.com/security/products/acrobat/apsb22-16.html'],
        "tags": ['pdf', 'cve-2022-28244', 'richmedia', 'csp', 'acrobat'],
    }

    PDF_GENERATORS = (
        write_richmedia_csp_bypass,
    )

    CVE_IDS = ['CVE-2022-28244']
    MODULE_TITLE = 'PDF CVE-2022-28244 RichMedia CSP Bypass'

    def run(self):
        return self.run_pdf_cve()