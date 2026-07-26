#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic Moodle helpers for exploit and scanner modules.

Provides path helpers, fingerprinting, version detection (lib/upgrade.txt),
and authenticated login. CVE-specific exploit logic belongs in modules.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

from core.framework.base_module import BaseModule

_MOODLE_JS_RE = re.compile(r'"moodle"\s*:\s*\{\s*"name"\s*:\s*"moodle"', re.IGNORECASE)
_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\'][^>]+content=["\']Moodle\s+([0-9][0-9.]*)',
    re.IGNORECASE,
)
_UPGRADE_VERSION_RE = re.compile(r"===\s*(\d+\.\d+(?:\.\d+)*)\s*===", re.IGNORECASE)
_SESSKEY_JSON_RE = re.compile(r'"sesskey"\s*:\s*"([^"]+)"')
_SESSKEY_INPUT_RE = re.compile(
    r'name=["\']sesskey["\'][^>]*value=["\']([^"\']+)["\']'
    r'|value=["\']([^"\']+)["\'][^>]*name=["\']sesskey["\']',
    re.IGNORECASE,
)
_LOGINTOKEN_RE = re.compile(
    r'name=["\']logintoken["\'][^>]*value=["\']([^"\']*)["\']'
    r'|value=["\']([^"\']*)["\'][^>]*name=["\']logintoken["\']',
    re.IGNORECASE,
)


class Moodle(BaseModule):
    """Moodle HTTP helper mixin for exploit/scanner modules."""

    @staticmethod
    def moodle_normalize_base_path(path_value: str) -> str:
        value = (path_value or "/").strip()
        if value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @classmethod
    def moodle_join_path(cls, base_path: str, *parts: str) -> str:
        root = cls.moodle_normalize_base_path(base_path)
        clean = [p.strip("/") for p in parts if p and str(p).strip("/")]
        if not clean:
            return root
        if root == "/":
            return "/" + "/".join(clean)
        return root + "/" + "/".join(clean)

    @staticmethod
    def moodle_parse_version_parts(version: str) -> List[int]:
        parts: List[int] = []
        for token in str(version or "").strip().split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return parts

    @classmethod
    def moodle_version_compare(cls, left: str, right: str) -> int:
        """Return -1 / 0 / 1 for left < / == / > right."""
        a = cls.moodle_parse_version_parts(left)
        b = cls.moodle_parse_version_parts(right)
        for i in range(max(len(a), len(b))):
            av = a[i] if i < len(a) else 0
            bv = b[i] if i < len(b) else 0
            if av < bv:
                return -1
            if av > bv:
                return 1
        return 0

    @classmethod
    def moodle_version_greater_than(cls, version: str, threshold: str) -> bool:
        if not version or not threshold:
            return False
        return cls.moodle_version_compare(version, threshold) > 0

    def moodle_login_path(self, base_path: str = None) -> str:
        root = self.moodle_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        return self.moodle_join_path(root, "login", "index.php")

    def moodle_upgrade_txt_path(self, base_path: str = None) -> str:
        root = self.moodle_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        return self.moodle_join_path(root, "lib", "upgrade.txt")

    @staticmethod
    def moodle_extract_sesskey(html: str) -> Optional[str]:
        if not html:
            return None
        match = _SESSKEY_JSON_RE.search(html)
        if match:
            return match.group(1)
        match = _SESSKEY_INPUT_RE.search(html)
        if match:
            return match.group(1) or match.group(2)
        return None

    @staticmethod
    def moodle_extract_logintoken(html: str) -> str:
        if not html:
            return ""
        match = _LOGINTOKEN_RE.search(html)
        if match:
            return match.group(1) or match.group(2) or ""
        return ""

    def moodle_detect(self, base_path: str = None, timeout: float = None) -> dict:
        """Fingerprint Moodle. Returns ``found``, ``version``, ``evidence``, ``base_path``."""
        timeout = float(timeout if timeout is not None else getattr(self, "timeout", None) or 15)
        root = self.moodle_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        evidence: List[str] = []
        version: Optional[str] = None

        response = self.http_request(
            method="GET",
            path=root if root != "/" else "/",
            allow_redirects=True,
            timeout=timeout,
        )
        if response and response.status_code == 200 and response.text:
            body = response.text
            if _MOODLE_JS_RE.search(body):
                evidence.append("moodle js config")
            gen = _GENERATOR_RE.search(body)
            if gen:
                evidence.append("generator")
                version = gen.group(1).strip()
            low = body.lower()
            if "moodle" in low and ("login/index.php" in low or "theme/boost" in low):
                evidence.append("moodle markers")

        version = self.moodle_version(base_path=root, timeout=timeout) or version
        if version:
            evidence.append("lib/upgrade.txt" if "lib/upgrade.txt" not in evidence else "version")

        login = self.http_request(
            method="GET",
            path=self.moodle_login_path(root),
            allow_redirects=True,
            timeout=timeout,
        )
        if login and login.status_code in (200, 301, 302, 403):
            body = (login.text or "").lower()
            if "logintoken" in body or ("username" in body and "password" in body):
                evidence.append("login/index.php")

        # Deduplicate while preserving order
        seen = set()
        unique_evidence = []
        for item in evidence:
            if item not in seen:
                seen.add(item)
                unique_evidence.append(item)

        return {
            "found": bool(unique_evidence),
            "version": version,
            "evidence": unique_evidence,
            "base_path": root,
        }

    def moodle_version(self, base_path: str = None, timeout: float = None) -> Optional[str]:
        """Read Moodle version from ``lib/upgrade.txt`` (Metasploit-compatible)."""
        timeout = float(timeout if timeout is not None else getattr(self, "timeout", None) or 15)
        path = self.moodle_upgrade_txt_path(base_path)
        response = self.http_request(
            method="GET",
            path=path,
            allow_redirects=True,
            timeout=timeout,
        )
        if not response or response.status_code != 200 or not response.text:
            return None
        match = _UPGRADE_VERSION_RE.search(response.text)
        return match.group(1) if match else None

    def moodle_login(
        self,
        username: str,
        password: str,
        *,
        base_path: str = None,
        timeout: float = None,
    ) -> Tuple[bool, Any]:
        """Authenticate against Moodle login. Returns ``(success, response)``."""
        timeout = float(timeout if timeout is not None else getattr(self, "timeout", None) or 20)
        root = self.moodle_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        login_path = self.moodle_login_path(root)

        pre = self.http_request(
            method="GET",
            path=login_path,
            allow_redirects=True,
            timeout=timeout,
        )
        if not pre:
            return False, pre

        token = self.moodle_extract_logintoken(pre.text or "")
        response = self.http_request(
            method="POST",
            path=login_path,
            data={
                "username": username,
                "password": password,
                "logintoken": token,
                "anchor": "",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=timeout,
        )
        if not response:
            return False, response

        body = response.text or ""
        body_low = body.lower()
        final_url = (getattr(response, "url", "") or "").lower()
        cookie_blob = ""
        try:
            session = getattr(self, "session", None)
            if session is not None and getattr(session, "cookies", None) is not None:
                cookie_blob = "; ".join(
                    f"{name}={value}" for name, value in session.cookies.items()
                )
        except Exception:
            cookie_blob = ""

        # Metasploit checks for " Dashboard"; also accept session cookies / non-login landing.
        if "invalidlogin" in body_low:
            return False, response
        if " Dashboard" in body or "dashboard" in body_low:
            if "login/index.php" not in final_url:
                return True, response
        if "MoodleSession" in cookie_blob:
            if "logintoken" not in body_low:
                return True, response
        if response.status_code == 200 and "login/index.php" not in final_url:
            if "sesskey" in body_low and "logintoken" not in body_low:
                return True, response
        return False, response
