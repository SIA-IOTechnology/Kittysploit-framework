"""PDF phone-home mixins for Auxiliary modules (BaseModule helpers, not Auxiliary subclasses)."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, List, Sequence

from core.framework.base_module import BaseModule
from core.framework.option import OptBool, OptChoice, OptString
from core.output_handler import print_info, print_success, print_warning
from core.framework.failure import fail
from lib.pdf.generate import (
    format_generator_slugs,
    generator_slug,
    run_generators,
    validate_callback_host,
)

Generator = Callable[..., None]


def format_test_ids(generators: Sequence[Generator]) -> str:
    return format_generator_slugs(generators)


class PdfPhonehomeMixin(BaseModule):
    """Shared options and helpers for PDF phone-home Auxiliary modules."""

    PDF_GENERATORS: Sequence[Generator] = ()
    MODULE_TITLE = "PDF phone-home generator"

    callback_url = OptString(
        "",
        "Callback URL or IP (Burp Collaborator, interact.sh, etc.)",
        required=True,
    )
    output_dir = OptString(
        "output/pdf",
        "Directory for generated files",
        required=False,
    )
    tests = OptString(
        "all",
        "Comma-separated generator slugs or 'all'",
        required=False,
    )
    obfuscate = OptChoice(
        "0",
        "Obfuscation level (0=none, 7=max; 7=anti-emulation guards)",
        required=False,
        choices=["0", "1", "2", "3", "4", "5", "6", "7"],
    )
    credit = OptBool(
        True,
        "Embed attribution metadata in generated PDFs",
        required=False,
    )

    def _generators(self) -> List[Generator]:
        gens = getattr(self, "PDF_GENERATORS", None) or ()
        return list(gens)

    def _scope_label(self) -> str:
        gens = self._generators()
        return f"{len(gens)} PoC file(s)"

    def run_pdf_phonehome(self) -> bool:
        generators = self._generators()
        if not generators:
            fail.Message("PDF_GENERATORS is not configured for this module.")
            return False

        host = str(self.callback_url or "").strip()
        if not validate_callback_host(host):
            fail.Message(
                "Invalid CALLBACK_URL. Use https://your-collaborator or a valid IP address."
            )
            return False

        output_dir = Path(str(self.output_dir or "output/pdf"))
        tests = str(self.tests or "all")
        obfuscate = int(str(self.obfuscate or "0"))
        credit = bool(self.credit)

        refs = self.__class__.__info__.get("references") or []
        print_info(f"[+] {self.MODULE_TITLE}")
        print_info(f"    Scope:    {self._scope_label()}")
        print_info(f"    Callback: {host}")
        print_info(f"    Output:   {output_dir.resolve()}")

        try:
            created = run_generators(
                host,
                output_dir,
                generators,
                tests=tests,
                obfuscate=obfuscate,
                credit=credit,
            )
        except ValueError as exc:
            fail.Message(str(exc))
            return False

        if not created:
            available = format_generator_slugs(generators)
            fail.Message(
                f"No PDFs generated. Check TESTS filter (available: {available})."
            )
            return False

        for path in created:
            print_success(f"    {path.name}")

        print_warning(
            "Authorized testing only. Pair with an HTTP/DNS listener to confirm callbacks."
        )
        for ref in refs:
            print_info(f"    Ref: {ref}")
        return True


class PdfCveMixin(PdfPhonehomeMixin):
    """Mixin for single-CVE PDF phone-home Auxiliary modules."""

    PDF_GENERATORS: Sequence[Generator] = ()
    CVE_IDS: List[str] = []

    def _scope_label(self) -> str:
        cve_label = ", ".join(self.CVE_IDS) if self.CVE_IDS else "CVE"
        return f"{cve_label} — {len(self._generators())} PoC file(s)"

    def run_pdf_cve(self) -> bool:
        if not self._generators():
            fail.Message("PDF_GENERATORS is not configured for this CVE module.")
            return False
        print_info(f"    PoCs:     {format_generator_slugs(self._generators())}")
        return self.run_pdf_phonehome()
