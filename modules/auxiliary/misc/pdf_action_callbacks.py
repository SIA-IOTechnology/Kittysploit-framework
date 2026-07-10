#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids
from lib.pdf.generators.actions import write_gotoe_unc, write_gotoe_https, write_uri_action, write_launch_url, write_gotor_remote, write_submitform_html, write_import_data, write_gotoe_javascript_uri, write_uri_paren_injection, write_xobject_remote_url, write_thread_remote_filespec, write_launch_print_fetch, write_names_javascript_trigger, write_pdfium_openaction_uri


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF Action Callback Generator",
        "description": (
            "Generate PDFs that trigger outbound requests via native PDF actions: "
            "/URI, /Launch, /GoToR, /GoToE, /SubmitForm, /ImportData, /Thread, "
            "XObject streams, and catalog /Names JavaScript triggers."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://github.com/RUB-NDS/PDF101",
        ],
        "tags": ["pdf", "phone-home", "actions", "ssrf", "callback"],
    }

    PDF_GENERATORS = (
        write_gotoe_unc,
        write_gotoe_https,
        write_uri_action,
        write_launch_url,
        write_gotor_remote,
        write_submitform_html,
        write_import_data,
        write_gotoe_javascript_uri,
        write_uri_paren_injection,
        write_xobject_remote_url,
        write_thread_remote_filespec,
        write_launch_print_fetch,
        write_names_javascript_trigger,
        write_pdfium_openaction_uri,
    )

    MODULE_TITLE = "PDF action callback generator"

    def run(self):
        print_info(f"    Test ids: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()