#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.pdf.mixins import PdfPhonehomeMixin, format_test_ids
from lib.pdf.generators.javascript import write_js_open_doc, write_foxit_geturl_js, write_js_xxe_xmldata, write_paren_inject_js_action, write_annot_page_visible_js, write_annot_page_close_js, write_submitform_exfil_pdf, write_js_submitform_pdf, write_widget_btn_cover_js, write_widget_tx_submitform, write_get_page_nth_word_exfil, write_annot_mouseover_js, write_acrobat_js_submit_form, write_acrobat_js_get_url, write_acrobat_js_launch_url, write_acrobat_js_media_geturl, write_acrobat_js_soap_connect, write_acrobat_js_soap_request, write_acrobat_js_import_data, write_acrobat_js_open_doc, write_browser_js_fetch, write_browser_js_xhr, write_browser_js_image, write_browser_js_websocket, write_acrobat_js_rss_addfeed, write_acrobat_js_readfile_chain, write_acrobat_js_field_staged
from lib.pdf.generators.viewer_cve import write_foxit_ocg_signing_js


class Module(Auxiliary, PdfPhonehomeMixin):
    __info__ = {
        "name": "PDF JavaScript Callback Generator",
        "description": (
            "Generate PDFs with JavaScript phone-home payloads for Acrobat, Foxit, "
            "PDF.js and browser contexts. Includes OpenAction, annotation triggers, "
            "widget buttons, submitForm exfiltration, and per-API isolated test cases "
            "(getURL, launchURL, SOAP, fetch, XHR, WebSocket, staged loaders)."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://portswigger.net/research/portable-data-exfiltration",
            "https://github.com/RUB-NDS/PDF101",
        ],
        "tags": ["pdf", "javascript", "phone-home", "acrobat", "pdfjs", "callback"],
    }

    PDF_GENERATORS = (
        write_js_open_doc,
        write_foxit_geturl_js,
        write_js_xxe_xmldata,
        write_paren_inject_js_action,
        write_annot_page_visible_js,
        write_annot_page_close_js,
        write_submitform_exfil_pdf,
        write_js_submitform_pdf,
        write_widget_btn_cover_js,
        write_widget_tx_submitform,
        write_get_page_nth_word_exfil,
        write_annot_mouseover_js,
        write_foxit_ocg_signing_js,
        write_acrobat_js_submit_form,
        write_acrobat_js_get_url,
        write_acrobat_js_launch_url,
        write_acrobat_js_media_geturl,
        write_acrobat_js_soap_connect,
        write_acrobat_js_soap_request,
        write_acrobat_js_import_data,
        write_acrobat_js_open_doc,
        write_browser_js_fetch,
        write_browser_js_xhr,
        write_browser_js_image,
        write_browser_js_websocket,
        write_acrobat_js_rss_addfeed,
        write_acrobat_js_readfile_chain,
        write_acrobat_js_field_staged,
    )

    MODULE_TITLE = "PDF JavaScript callback generator"

    def run(self):
        print_info(f"    Test ids: {format_test_ids(self.PDF_GENERATORS)}")
        return self.run_pdf_phonehome()