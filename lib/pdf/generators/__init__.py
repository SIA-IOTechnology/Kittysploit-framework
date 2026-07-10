"""PDF phone-home PoC generators."""

from __future__ import annotations


from lib.pdf.generators.actions import write_gotoe_unc, write_gotoe_https, write_uri_action, write_launch_url, write_gotor_remote, write_submitform_html, write_import_data, write_gotoe_javascript_uri, write_uri_paren_injection, write_xobject_remote_url, write_thread_remote_filespec, write_launch_print_fetch, write_names_javascript_trigger, write_pdfium_openaction_uri
from lib.pdf.generators.javascript import write_js_open_doc, write_foxit_geturl_js, write_js_xxe_xmldata, write_paren_inject_js_action, write_annot_page_visible_js, write_annot_page_close_js, write_submitform_exfil_pdf, write_js_submitform_pdf, write_widget_btn_cover_js, write_widget_tx_submitform, write_get_page_nth_word_exfil, write_annot_mouseover_js, write_acrobat_js_submit_form, write_acrobat_js_get_url, write_acrobat_js_launch_url, write_acrobat_js_media_geturl, write_acrobat_js_soap_connect, write_acrobat_js_soap_request, write_acrobat_js_import_data, write_acrobat_js_open_doc, write_browser_js_fetch, write_browser_js_xhr, write_browser_js_image, write_browser_js_websocket, write_acrobat_js_rss_addfeed, write_acrobat_js_readfile_chain, write_acrobat_js_field_staged
from lib.pdf.generators.xfa import write_xfa_submit, write_xfa_xslt_callback, write_xfa_formcalc_post, write_xfa_crlf_submit, write_formcalc_post_headers, write_xfa_soap_submit
from lib.pdf.generators.xxe import write_xxe_xmp_metadata, write_xxe_xfa_acroform, write_xfa_xxe_oob
from lib.pdf.generators.unc import write_unc_xobject, write_unc_gotor, write_unc_thread, write_unc_uri, write_unc_js_submit_form, write_unc_js_get_url, write_unc_js_launch_url, write_unc_js_soap, write_unc_js_open_doc
from lib.pdf.generators.viewer_cve import write_pdfjs_fontmatrix, write_richmedia_csp_bypass, write_pdfjs_postscript_js, write_annot_author_xss, write_libreoffice_expand_uri, write_foxit_ocg_signing_js, write_jspdf_object_injection, write_pdf20_associated_files_html, _CMBX12_FONT_B64
from lib.pdf.generators.polyglot import write_eicar_polyglot, write_imagemagick_svg_polyglot
from lib.pdf.generators.silent import write_silent_dns_catalog_aa


__all__ = [
    "write_gotoe_unc",
    "write_gotoe_https",
    "write_uri_action",
    "write_launch_url",
    "write_gotor_remote",
    "write_submitform_html",
    "write_import_data",
    "write_gotoe_javascript_uri",
    "write_uri_paren_injection",
    "write_xobject_remote_url",
    "write_thread_remote_filespec",
    "write_launch_print_fetch",
    "write_names_javascript_trigger",
    "write_pdfium_openaction_uri",
    "write_js_open_doc",
    "write_foxit_geturl_js",
    "write_js_xxe_xmldata",
    "write_paren_inject_js_action",
    "write_annot_page_visible_js",
    "write_annot_page_close_js",
    "write_submitform_exfil_pdf",
    "write_js_submitform_pdf",
    "write_widget_btn_cover_js",
    "write_widget_tx_submitform",
    "write_get_page_nth_word_exfil",
    "write_annot_mouseover_js",
    "write_acrobat_js_submit_form",
    "write_acrobat_js_get_url",
    "write_acrobat_js_launch_url",
    "write_acrobat_js_media_geturl",
    "write_acrobat_js_soap_connect",
    "write_acrobat_js_soap_request",
    "write_acrobat_js_import_data",
    "write_acrobat_js_open_doc",
    "write_browser_js_fetch",
    "write_browser_js_xhr",
    "write_browser_js_image",
    "write_browser_js_websocket",
    "write_acrobat_js_rss_addfeed",
    "write_acrobat_js_readfile_chain",
    "write_acrobat_js_field_staged",
    "write_xfa_submit",
    "write_xfa_xslt_callback",
    "write_xfa_formcalc_post",
    "write_xfa_crlf_submit",
    "write_formcalc_post_headers",
    "write_xfa_soap_submit",
    "write_xxe_xmp_metadata",
    "write_xxe_xfa_acroform",
    "write_xfa_xxe_oob",
    "write_unc_xobject",
    "write_unc_gotor",
    "write_unc_thread",
    "write_unc_uri",
    "write_unc_js_submit_form",
    "write_unc_js_get_url",
    "write_unc_js_launch_url",
    "write_unc_js_soap",
    "write_unc_js_open_doc",
    "write_pdfjs_fontmatrix",
    "write_richmedia_csp_bypass",
    "write_pdfjs_postscript_js",
    "write_annot_author_xss",
    "write_libreoffice_expand_uri",
    "write_foxit_ocg_signing_js",
    "write_jspdf_object_injection",
    "write_pdf20_associated_files_html",
    "_CMBX12_FONT_B64",
    "write_eicar_polyglot",
    "write_imagemagick_svg_polyglot",
    "write_silent_dns_catalog_aa",
]
