#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf import generators
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF Phone-Home Full Suite",
        "description": (
            "Generate the full KittySploit PDF phone-home suite (~70 files) with phone-home "
            "callbacks for upload-scanner and red-team validation. Covers URI actions, "
            "JavaScript, XFA, XXE, UNC/NTLM, and viewer-specific CVE PoCs."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://github.com/RUB-NDS/PDF101",
            "https://portswigger.net/research/portable-data-exfiltration",
        ],
        "tags": ["pdf", "phone-home", "callback", "red-team", "upload-scanner"],
    }

    PDF_GENERATORS = tuple(
        getattr(generators, name)
        for name in generators.__all__
        if name.startswith("write_")
    )
    MODULE_TITLE = "PDF phone-home full suite"

    def run(self):
        print_info(f"    Generators: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()
