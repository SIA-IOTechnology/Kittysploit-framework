#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic MediaWiki HTTP helpers for scanner / auxiliary modules."""

from __future__ import annotations

import random
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from core.framework.base_module import BaseModule


_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']MediaWiki\s+([\d.]+)["\']',
    re.I,
)
_VERSION_IN_TEXT_RE = re.compile(r"MediaWiki\s+([\d.]+)", re.I)

_LOGITEM_XML_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<mediawiki xmlns="http://www.mediawiki.org/xml/export-0.11/" \
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xsi:schemaLocation="http://www.mediawiki.org/xml/export-0.11/ \
http://www.mediawiki.org/xml/export-0.11.xsd" version="0.11" xml:lang="en">
<logitem>
\t<id>{log_id}</id>
\t<timestamp>{timestamp}</timestamp>
\t<contributor>
\t\t<username>{username}</username>
\t\t<id>{user_id}</id>
\t</contributor>
\t<comment>{comment}</comment>
\t<type>{log_type}</type>
\t<action>{log_action}</action>
\t<logtitle>{log_title}</logtitle>
\t<params>{params}</params>
</logitem>
</mediawiki>
"""


class Mediawiki(BaseModule):
    """Reusable MediaWiki path / fingerprint / import helpers."""

    @staticmethod
    def mw_parse_version(version: str) -> Optional[Tuple[int, ...]]:
        raw = str(version or "").strip()
        if not raw:
            return None
        parts: List[int] = []
        for chunk in raw.split("."):
            if not chunk.isdigit():
                break
            parts.append(int(chunk))
        return tuple(parts) if parts else None

    @staticmethod
    def mw_normalize_base_path(base_path: str) -> str:
        path = str(base_path or "").strip()
        if not path or path == "/":
            return ""
        if not path.startswith("/"):
            path = "/" + path
        return path.rstrip("/")

    @staticmethod
    def mw_join_path(base_path: str, suffix: str) -> str:
        base = Mediawiki.mw_normalize_base_path(base_path)
        suf = str(suffix or "")
        if not suf.startswith("/"):
            suf = "/" + suf
        return f"{base}{suf}"

    @staticmethod
    def mw_parse_cookie_header(cookie: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for part in str(cookie or "").split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            if key:
                out[key] = value.strip()
        return out

    @staticmethod
    def mw_extract_edit_token(html: str) -> str:
        body = str(html or "")
        patterns = (
            r'name=["\']wpEditToken["\']\s+value=["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\']\s+name=["\']wpEditToken["\']',
            r'"wpEditToken"\s*:\s*"([^"]+)"',
            r'name=["\']token["\']\s+value=["\']([^"\']+)["\']',
        )
        for pattern in patterns:
            match = re.search(pattern, body, re.I)
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def mw_fingerprint_html(html: str) -> Dict[str, Any]:
        """Return detected/version from page HTML (no CVE verdict)."""
        body = str(html or "")
        findings: Dict[str, Any] = {"detected": False, "version": ""}
        match = _GENERATOR_RE.search(body)
        if match:
            findings["detected"] = True
            findings["version"] = match.group(1)
            return findings
        if "mediawiki" in body.lower():
            findings["detected"] = True
            alt = _VERSION_IN_TEXT_RE.search(body)
            findings["version"] = alt.group(1) if alt else "unknown"
        return findings

    @staticmethod
    def mw_fingerprint_siteinfo(data: Dict[str, Any]) -> Dict[str, Any]:
        """Return detected/version/generator from api.php siteinfo JSON."""
        findings: Dict[str, Any] = {
            "detected": False,
            "version": "",
            "generator": "",
        }
        general = ((data or {}).get("query") or {}).get("general") or {}
        generator = str(general.get("generator") or "")
        findings["generator"] = generator
        match = _VERSION_IN_TEXT_RE.search(generator)
        if match:
            findings["detected"] = True
            findings["version"] = match.group(1)
            return findings
        if generator:
            findings["detected"] = True
            findings["version"] = "unknown"
        return findings

    @staticmethod
    def mw_build_logitem_xml(
        params: str,
        *,
        username: str = "WikiImporter",
        comment: str = "MediaWiki import",
        log_title: str = "Import",
        log_type: str = "test",
        log_action: str = "test",
    ) -> str:
        """Build a minimal MediaWiki export XML containing one <logitem>."""
        return _LOGITEM_XML_TEMPLATE.format(
            log_id=random.randint(1, 999999),
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            username=xml_escape(username or "WikiImporter"),
            user_id=random.randint(1, 99999),
            comment=xml_escape(comment),
            log_type=xml_escape(log_type),
            log_action=xml_escape(log_action),
            log_title=xml_escape(log_title),
            params=xml_escape(params or ""),
        )

    @staticmethod
    def mw_classify_import_response(
        status: int, body: str, location: str = ""
    ) -> Dict[str, Any]:
        """Classify a Special:Import HTTP response."""
        text = str(body or "")
        low = text.lower()
        loc = str(location or "").lower()
        result: Dict[str, Any] = {
            "status": int(status or 0),
            "success": False,
            "needs_auth": False,
            "denied": False,
            "error": "",
            "message": "",
        }
        if status in (301, 302, 303, 307, 308) and "login" in loc:
            result["needs_auth"] = True
            result["message"] = "redirected to login"
            return result
        if "permission" in low or "denied" in low or "not allowed" in low:
            result["denied"] = True
            result["message"] = "permission denied"
            return result
        if status == 200 and (
            ("importsuccessful" in low)
            or ("import-logentry" in low)
            or ("successfully imported" in low)
            or ("import completed" in low)
            or ("imported" in low and "error" not in low)
        ):
            result["success"] = True
            result["message"] = "import appears successful"
            return result
        err = re.search(r'<p class="error">(.*?)</p>', text, re.I | re.S)
        if err:
            result["error"] = re.sub(r"\s+", " ", err.group(1)).strip()[:240]
            result["message"] = result["error"]
            return result
        if status == 200 and (
            "xmlimport" in low or "special:import" in low or "wpedittoken" in low
        ):
            result["message"] = "import form returned; outcome unclear"
            return result
        result["message"] = f"unclear response (HTTP {status})"
        return result
