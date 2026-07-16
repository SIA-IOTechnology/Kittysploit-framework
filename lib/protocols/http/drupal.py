#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic Drupal helpers for exploit and scanner modules.

Provides password hashing compatible with Drupal 6/7, path helpers,
version detection, and lightweight fingerprinting. CVE-specific exploit
logic belongs in modules, not here.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, List, Optional, Tuple
from urllib.parse import quote

from core.framework.base_module import BaseModule
from lib.scanner.http.detectors import detect_drupal

# Drupal stores phpass-style hashes truncated to this length (includes settings prefix).
DRUPAL_HASH_LENGTH = 55

# Well-known PHP warning emitted when the login form receives an array for ``name``
# after expandArguments runs injected SQL (used by SA-CORE-2014-005 checks).
DRUPAL_LOGIN_ARRAY_WARNING = "mb_strlen() expects parameter 1"

_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\'][^>]+content=["\']Drupal\s+([0-9][0-9.]*)',
    re.IGNORECASE,
)
_CHANGELOG_RE = re.compile(r"Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)


class DrupalHash:
    """Drupal 6/7 compatible password hasher (phpass / Drupal ``password.inc``)."""

    ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def __init__(self, stored_hash: str, password: str):
        self.last_hash = self.rehash(stored_hash, password)

    def get_hash(self) -> Optional[str]:
        return self.last_hash

    @classmethod
    def password_get_count_log2(cls, setting: str) -> int:
        return cls.ITOA64.index(setting[3])

    @classmethod
    def custom64(cls, data: bytes, count: int = 0) -> str:
        if count == 0:
            count = len(data)
        output: List[str] = []
        i = 0
        itoa64 = cls.ITOA64
        while True:
            value = data[i]
            i += 1
            output.append(itoa64[value & 0x3F])
            if i < count:
                value |= data[i] << 8
            output.append(itoa64[(value >> 6) & 0x3F])
            if i >= count:
                break
            i += 1
            if i < count:
                value |= data[i] << 16
            output.append(itoa64[(value >> 12) & 0x3F])
            if i >= count:
                break
            i += 1
            output.append(itoa64[(value >> 18) & 0x3F])
            if i >= count:
                break
        return "".join(output)

    @classmethod
    def password_crypt(cls, algo: str, password: str, setting: str) -> Optional[str]:
        setting = setting[:12]
        if len(setting) < 12 or setting[0] != "$" or setting[2] != "$":
            return None

        try:
            count_log2 = cls.password_get_count_log2(setting)
        except ValueError:
            return None

        salt = setting[4:12]
        if len(salt) < 8:
            return None

        count = 1 << count_log2
        password_b = password.encode("utf-8")
        salt_b = salt.encode("utf-8")

        if algo == "md5":
            hash_func = hashlib.md5
        elif algo == "sha512":
            hash_func = hashlib.sha512
        else:
            return None

        digest = hash_func(salt_b + password_b).digest()
        for _ in range(count):
            digest = hash_func(digest + password_b).digest()
        return setting + cls.custom64(digest)

    @classmethod
    def rehash(cls, stored_hash: str, password: str) -> Optional[str]:
        stored_hash = (stored_hash or "").strip()
        if not stored_hash:
            return None

        # Drupal 6 MD5 (32 hex chars, no $)
        if len(stored_hash) == 32 and "$" not in stored_hash:
            return hashlib.md5(password.encode("utf-8")).hexdigest()

        # Drupal 7 hash of a Drupal 6 MD5 (U$ prefix)
        if stored_hash.startswith("U$"):
            stored_hash = stored_hash[1:]
            password = hashlib.md5(password.encode("utf-8")).hexdigest()

        hash_type = stored_hash[:3]
        if hash_type == "$S$":
            return cls.password_crypt("sha512", password, stored_hash)
        if hash_type in ("$H$", "$P$"):
            return cls.password_crypt("md5", password, stored_hash)
        return None

    @classmethod
    def hash_password(
        cls,
        password: str,
        *,
        setting: str = "$S$CTo9G7Lx28rzCfpn4WB2hUlknDKv6QTqHaf82WLbhPT2K5TzKzML",
        truncate: bool = True,
    ) -> Optional[str]:
        """Hash *password* using *setting* as algorithm/iteration/salt template."""
        result = cls.rehash(setting, password)
        if result and truncate:
            return result[:DRUPAL_HASH_LENGTH]
        return result


class Drupal(BaseModule):
    """Drupal HTTP helper mixin for exploit/scanner modules."""

    @staticmethod
    def drupal_normalize_base_path(path_value: str) -> str:
        value = (path_value or "/").strip()
        if value == "/":
            return "/"
        if not value.startswith("/"):
            value = "/" + value
        return "/" + value.strip("/")

    @classmethod
    def drupal_join_path(cls, base_path: str, *parts: str) -> str:
        root = cls.drupal_normalize_base_path(base_path)
        clean = [p.strip("/") for p in parts if p and str(p).strip("/")]
        if not clean:
            return root
        if root == "/":
            return "/" + "/".join(clean)
        return root + "/" + "/".join(clean)

    @staticmethod
    def drupal_parse_version_parts(version: str) -> List[int]:
        parts: List[int] = []
        for token in str(version or "").strip().split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return parts

    @classmethod
    def drupal_version_compare(cls, left: str, right: str) -> int:
        """Return -1 / 0 / 1 for left < / == / > right."""
        a = cls.drupal_parse_version_parts(left)
        b = cls.drupal_parse_version_parts(right)
        for i in range(max(len(a), len(b))):
            av = a[i] if i < len(a) else 0
            bv = b[i] if i < len(b) else 0
            if av < bv:
                return -1
            if av > bv:
                return 1
        return 0

    @classmethod
    def drupal_version_less_than(cls, version: str, threshold: str) -> bool:
        if not version or not threshold:
            return False
        return cls.drupal_version_compare(version, threshold) < 0

    @staticmethod
    def drupal_extract_version_from_html(body: str) -> Optional[str]:
        if not body:
            return None
        match = _GENERATOR_RE.search(body)
        return match.group(1).strip() if match else None

    @staticmethod
    def drupal_extract_version_from_changelog(text: str) -> Optional[str]:
        if not text:
            return None
        match = _CHANGELOG_RE.search(text)
        return match.group(1).strip() if match else None

    @staticmethod
    def drupal_hash_password(password: str, **kwargs: Any) -> Optional[str]:
        return DrupalHash.hash_password(password, **kwargs)

    @staticmethod
    def drupal_sql_quote(value: str) -> str:
        """Escape a string for embedding in a raw SQL literal (single-quoted)."""
        return (value or "").replace("\\", "\\\\").replace("'", "''")

    @staticmethod
    def drupal_table(name: str, prefix: str = "") -> str:
        return f"{prefix or ''}{name}"

    def drupal_login_block_path(self, base_path: str = None) -> str:
        """Path used by many Drupal 7 installs for the login block form POST."""
        root = self.drupal_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        if root == "/":
            return "/?q=node&destination=node"
        return f"{root}/?q=node&destination=node"

    def drupal_user_login_path(self, base_path: str = None) -> str:
        root = self.drupal_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        return self.drupal_join_path(root, "user", "login")

    def drupal_detect(self, base_path: str = None, timeout: float = None) -> dict:
        """Fingerprint Drupal on the target. Returns ``found``, ``version``, ``evidence``."""
        timeout = float(timeout if timeout is not None else getattr(self, "timeout", None) or 15)
        root = self.drupal_normalize_base_path(
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
        if response and detect_drupal(response):
            evidence.append("homepage markers")
            version = self.drupal_extract_version_from_html(response.text or "") or version

        for changelog_path in (
            self.drupal_join_path(root, "CHANGELOG.txt"),
            self.drupal_join_path(root, "core", "CHANGELOG.txt"),
        ):
            cl = self.http_request(
                method="GET",
                path=changelog_path,
                allow_redirects=True,
                timeout=timeout,
            )
            if cl and cl.status_code == 200 and "drupal" in (cl.text or "").lower():
                evidence.append(changelog_path)
                version = self.drupal_extract_version_from_changelog(cl.text or "") or version
                break

        login = self.http_request(
            method="GET",
            path=self.drupal_user_login_path(root),
            allow_redirects=False,
            timeout=timeout,
        )
        if login and login.status_code in (200, 301, 302, 403):
            body = (login.text or "").lower()
            if "form_id" in body and ("user_login" in body or "name" in body):
                evidence.append("user/login")

        return {
            "found": bool(evidence),
            "version": version,
            "evidence": evidence,
            "base_path": root,
        }

    def drupal_build_login_block_body(
        self,
        *,
        name_key: str,
        name_value: str = "test",
        password: str = "test",
        form_id: str = "user_login_block",
    ) -> str:
        """Build an ``application/x-www-form-urlencoded`` body for the login block.

        *name_key* is the raw ``name[...]`` parameter name (may contain SQL).
        """
        parts = [
            f"{name_key}={quote(name_value, safe='')}",
            f"name[0]={quote('test', safe='')}",
            f"pass={quote(password, safe='')}",
            "form_build_id=",
            f"form_id={quote(form_id, safe='')}",
            "op=Log+in",
        ]
        return "&".join(parts)

    def drupal_post_login_block(
        self,
        body: str,
        *,
        path: str = None,
        base_path: str = None,
        timeout: float = None,
        headers: dict = None,
    ):
        timeout = float(timeout if timeout is not None else getattr(self, "timeout", None) or 15)
        post_path = path or self.drupal_login_block_path(base_path)
        req_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if headers:
            req_headers.update(headers)
        return self.http_request(
            method="POST",
            path=post_path,
            data=body,
            headers=req_headers,
            allow_redirects=False,
            timeout=timeout,
        )

    @staticmethod
    def drupal_extract_login_form_fields(html: str) -> dict:
        """Extract hidden fields / form_id from a Drupal user login page."""
        fields: dict = {}
        if not html:
            return fields

        for match in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            tag = match.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                fields[name_m.group(1)] = value_m.group(1) if value_m else ""

        # form_id may also appear as a non-hidden input on some themes
        if "form_id" not in fields:
            form_id_m = re.search(
                r'name=["\']form_id["\'][^>]*value=["\']([^"\']+)["\']'
                r'|value=["\']([^"\']+)["\'][^>]*name=["\']form_id["\']',
                html,
                re.IGNORECASE,
            )
            if form_id_m:
                fields["form_id"] = form_id_m.group(1) or form_id_m.group(2) or ""

        if "form_id" not in fields:
            # Drupal 7 uses user_login; Drupal 8+ uses user_login_form
            low = html.lower()
            if "user_login_form" in low:
                fields["form_id"] = "user_login_form"
            else:
                fields["form_id"] = "user_login"

        submit_m = re.search(
            r'<input[^>]+type=["\']submit["\'][^>]*>',
            html,
            re.IGNORECASE,
        )
        if submit_m:
            tag = submit_m.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                fields[name_m.group(1)] = value_m.group(1) if value_m else "Log in"
            else:
                fields.setdefault("op", value_m.group(1) if value_m else "Log in")
        else:
            fields.setdefault("op", "Log in")

        return fields

    def drupal_try_login(
        self,
        username: str,
        password: str,
        *,
        base_path: str = None,
        timeout: float = None,
        allow_redirects: bool = False,
        form_fields: dict = None,
    ) -> Tuple[bool, Any]:
        """Attempt a normal Drupal user login. Returns ``(success, response)``."""
        timeout = float(timeout if timeout is not None else getattr(self, "timeout", None) or 15)
        root = self.drupal_normalize_base_path(
            base_path if base_path is not None else getattr(self, "path", "/")
        )
        path = self.drupal_user_login_path(root)

        fields = dict(form_fields or {})
        if not fields:
            pre = self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=timeout,
            )
            fields = self.drupal_extract_login_form_fields(pre.text if pre else "")

        fields["name"] = username
        fields["pass"] = password
        fields.setdefault("form_id", "user_login")
        fields.setdefault("op", "Log in")

        response = self.http_request(
            method="POST",
            path=path,
            data=fields,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=allow_redirects,
            timeout=timeout,
        )
        if not response:
            return False, response

        # Successful login typically redirects away from /user/login
        location = (response.headers.get("Location") or "").lower()
        set_cookie = str(response.headers.get("Set-Cookie") or "")
        body_low = (response.text or "").lower()
        final_url = (getattr(response, "url", "") or "").lower()

        if response.status_code in (302, 303, 307, 308) and "/user/login" not in location:
            return True, response
        if allow_redirects and "/user/login" not in final_url:
            if "SESS" in set_cookie or "SSESS" in set_cookie or "logout" in body_low:
                return True, response
        if "SESS" in set_cookie or "SSESS" in set_cookie:
            if response.status_code in (200, 302, 303) and "sorry" not in body_low:
                # Failed Drupal logins often keep the form; success leaves login markers behind.
                if "user_login" not in body_low or "name=\"pass\"" not in body_low:
                    return True, response
        return False, response

    # Backward-compatible short aliases
    normalize_base_path = drupal_normalize_base_path
    join_path = drupal_join_path
    hash_password = drupal_hash_password
