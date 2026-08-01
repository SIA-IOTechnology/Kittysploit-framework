#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Academy command: browse KittySploit Academy tracks and certification docs."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from core.output_handler import print_empty, print_error, print_info, print_success, print_table, print_warning
from interfaces.command_system.base_command import BaseCommand


ACADEMY_ROOT = Path(__file__).resolve().parents[3] / "docs" / "academy"

ACADEMY_DOCS: Dict[str, str] = {
    "overview": "README.md",
    "plan": "plan.md",
    "ethics": "ethics.md",
    "kso": "kso-syllabus.md",
    "ksp": "ksp-syllabus.md",
    "exam-kso": "exam-kso.md",
    "qcm-kso": "qcm-bank-kso.md",
    "lab-kso-01": "lab-kso-01.md",
    "student-brief-kso-01": "student-brief-lab-01.md",
    "instructor-guide-kso-01": "instructor-guide-lab-01.md",
    "report-template-kso": "report-template-kso.md",
    "dry-run-beta": "dry-run-beta.md",
    "landing-wireframe": "landing-wireframe.md",
    "landing": "landing/index.html",
}

KSO_MODULES: List[Dict[str, str]] = [
    {"id": "m00", "title": "Ethics & ROE", "duration": "1-1.5 h", "doc": "modules/m00-ethics.md"},
    {"id": "m01", "title": "Installation", "duration": "2 h", "doc": "modules/m01-install.md"},
    {"id": "m02", "title": "Workspaces", "duration": "2 h", "doc": "modules/m02-workspaces.md"},
    {"id": "m03", "title": "Scanner", "duration": "3-4 h", "doc": "modules/m03-scanner.md"},
    {"id": "m04", "title": "Modules", "duration": "3 h", "doc": "modules/m04-modules.md"},
    {"id": "m05", "title": "Exploitation", "duration": "4 h", "doc": "modules/m05-exploit.md"},
    {"id": "m06", "title": "Post-exploitation", "duration": "2-3 h", "doc": "modules/m06-post.md"},
    {"id": "m07", "title": "Reporting", "duration": "2-3 h", "doc": "modules/m07-reporting.md"},
    {"id": "m08", "title": "Agent", "duration": "1.5-2 h", "doc": "modules/m08-agent.md"},
    {"id": "capstone", "title": "Capstone", "duration": "3-4 h", "doc": "modules/m09-capstone.md"},
]

CERTIFICATIONS: List[Dict[str, str]] = [
    {
        "code": "KSO",
        "name": "KittySploit Operator",
        "level": "Foundations",
        "status": "MVP ready for beta dry-run",
        "doc": "kso",
    },
    {
        "code": "KSP",
        "name": "KittySploit Professional",
        "level": "Advanced operations",
        "status": "Draft syllabus",
        "doc": "ksp",
    },
    {
        "code": "KSD",
        "name": "KittySploit Developer",
        "level": "Module authoring",
        "status": "Planned v2",
        "doc": "plan",
    },
]


class AcademyCommand(BaseCommand):
    """Browse Academy curriculum and certification material."""

    @property
    def name(self) -> str:
        return "academy"

    @property
    def description(self) -> str:
        return "Browse KittySploit Academy tracks, modules, labs, and certifications"

    @property
    def usage(self) -> str:
        return "academy [overview|tracks|certs|modules|show|path] [id]"

    def get_subcommands(self):
        return ["overview", "tracks", "certs", "modules", "show", "path"]

    @property
    def help_text(self) -> str:
        docs = ", ".join(sorted(ACADEMY_DOCS.keys()))
        return f"""
{self.description}

Usage: {self.usage}

Content source: docs/academy/

Subcommands:
    overview                  Show the Academy status and next steps
    tracks                    List learning tracks
    certs                     List certification badges and maturity
    modules                   List KSO course modules
    show <id> [--lines N]     Preview a document or KSO module
    path [id]                 Print the Academy root or a document path

Document ids:
    {docs}

Examples:
    academy
    academy certs
    academy modules
    academy show kso
    academy show m03 --lines 80
    academy path landing
        """

    def __init__(self, framework, session, output_handler):
        super().__init__(framework, session, output_handler)
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="academy",
            description="KittySploit Academy browser",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        subparsers = parser.add_subparsers(dest="action")
        subparsers.add_parser("overview", help="Show Academy overview")
        subparsers.add_parser("tracks", help="List learning tracks")
        subparsers.add_parser("certs", help="List certifications")
        subparsers.add_parser("modules", help="List KSO modules")

        show = subparsers.add_parser("show", help="Preview an Academy document")
        show.add_argument("doc_id")
        show.add_argument("--lines", type=int, default=60, help="Number of lines to preview")

        path = subparsers.add_parser("path", help="Print Academy path")
        path.add_argument("doc_id", nargs="?")
        return parser

    def execute(self, args, **kwargs) -> bool:
        try:
            parsed = self.parser.parse_args(args)
        except SystemExit:
            return True

        action = parsed.action or "overview"
        if action == "overview":
            return self._handle_overview()
        if action == "tracks":
            return self._handle_tracks()
        if action == "certs":
            return self._handle_certs()
        if action == "modules":
            return self._handle_modules()
        if action == "show":
            return self._handle_show(parsed.doc_id, parsed.lines)
        if action == "path":
            return self._handle_path(getattr(parsed, "doc_id", None))

        print_error(f"Unknown academy action: {action}")
        return False

    def _handle_overview(self) -> bool:
        if not ACADEMY_ROOT.exists():
            print_error(f"Academy docs directory not found: {ACADEMY_ROOT}")
            return False

        print_success("KittySploit Academy")
        print_info("Practical training and certifications built around the KittySploit workflow.")
        print_empty()
        self._handle_certs()
        print_empty()
        print_info("Next recommended actions:")
        print_info("  1. Run a human dry-run for KSO with 1-2 beta testers.")
        print_info("  2. Keep KSO as the first credible certification before expanding KSP.")
        print_info("  3. Integrate docs/academy/landing/index.html on the public site or subdomain.")
        print_empty()
        print_info("Use `academy modules` and `academy show kso` to browse the current content.")
        return True

    def _handle_tracks(self) -> bool:
        rows = [
            ["KSO", "Operator", "20-25 h", "Foundations, guided lab, exam"],
            ["KSP", "Professional", "8-10 weeks", "Advanced ops, C2, automation, reporting"],
            ["KSD", "Developer", "TBD", "Module authoring, tests, marketplace"],
        ]
        print_table(["Track", "Name", "Duration", "Scope"], rows)
        return True

    def _handle_certs(self) -> bool:
        rows = [[cert["code"], cert["name"], cert["level"], cert["status"], cert["doc"]] for cert in CERTIFICATIONS]
        print_table(["Code", "Certification", "Level", "Status", "Doc"], rows)
        return True

    def _handle_modules(self) -> bool:
        rows = [[item["id"], item["title"], item["duration"], item["doc"]] for item in KSO_MODULES]
        print_table(["ID", "KSO module", "Duration", "Doc"], rows)
        return True

    def _handle_show(self, doc_id: str, lines: int) -> bool:
        doc_path = self._resolve_doc(doc_id)
        if not doc_path:
            return False
        if not doc_path.is_file():
            print_error(f"Academy document not found: {doc_path}")
            return False

        max_lines = max(1, min(int(lines or 60), 300))
        print_info(f"{doc_id}: {self._relative(doc_path)}")
        print_info("-" * 72)
        try:
            with doc_path.open("r", encoding="utf-8", errors="replace") as handle:
                for index, line in enumerate(handle, start=1):
                    if index > max_lines:
                        print_warning(f"Preview truncated at {max_lines} lines. Use `academy path {doc_id}` for the full file.")
                        break
                    print_info(line.rstrip())
        except OSError as exc:
            print_error(f"Unable to read Academy document: {exc}")
            return False
        return True

    def _handle_path(self, doc_id: Optional[str]) -> bool:
        if not doc_id:
            print_info(str(ACADEMY_ROOT))
            return True
        doc_path = self._resolve_doc(doc_id)
        if not doc_path:
            return False
        print_info(str(doc_path))
        return doc_path.exists()

    def _resolve_doc(self, doc_id: str) -> Optional[Path]:
        normalized = str(doc_id or "").strip().lower()
        if not normalized:
            print_error("Document id is required")
            return None

        module_doc = self._module_doc(normalized)
        if module_doc:
            return self._safe_academy_path(module_doc)

        rel = ACADEMY_DOCS.get(normalized)
        if not rel:
            print_error(f"Unknown Academy document: {doc_id}")
            print_info("Use `academy modules`, `academy certs`, or `help academy` to list valid ids.")
            return None
        return self._safe_academy_path(rel)

    def _module_doc(self, doc_id: str) -> Optional[str]:
        for module in KSO_MODULES:
            if doc_id == module["id"] or doc_id == module["doc"].lower():
                return module["doc"]
        return None

    def _safe_academy_path(self, rel_path: str) -> Path:
        root = ACADEMY_ROOT.resolve()
        candidate = (root / rel_path).resolve()
        if root == candidate or root in candidate.parents:
            return candidate
        raise ValueError(f"Academy path escapes docs root: {rel_path}")

    def _relative(self, doc_path: Path) -> str:
        try:
            return str(doc_path.resolve().relative_to(ACADEMY_ROOT.resolve()))
        except ValueError:
            return str(doc_path)
