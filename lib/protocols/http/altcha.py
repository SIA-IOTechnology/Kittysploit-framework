#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""altcha proof-of-work CAPTCHA protocol helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict, Optional, Tuple

from core.framework.base_module import BaseModule


class Altcha(BaseModule):
    """Fetch challenges, solve PoW, and build altcha solution payloads."""

    REQUIRED_KEYS = ("challenge", "salt", "algorithm")

    @classmethod
    def hash_for_algorithm(cls, algorithm: str):
        name = str(algorithm or "SHA-256").upper().replace("-", "").lower()
        aliases = {
            "sha256": "sha256",
            "sha512": "sha512",
            "sha384": "sha384",
            "sha224": "sha224",
            "sha1": "sha1",
            "md5": "md5",
        }
        attr = aliases.get(name, name)
        fn = getattr(hashlib, attr, None)
        return fn or hashlib.sha256

    @classmethod
    def decode_challenge_response(
        cls,
        text: str,
        *,
        content_type: str = "",
        json_body: Any = None,
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Return (base64_payload, decoded_challenge_dict)."""
        data = json_body
        raw = (text or "").strip()
        if data is None and raw:
            if raw.startswith("{") or raw.startswith("["):
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = None
            else:
                data = None

        challenge_b64 = ""
        if isinstance(data, dict):
            challenge_b64 = str(
                data.get("challenge")
                or data.get("payload")
                or data.get("altcha")
                or ""
            ).strip()
            if not challenge_b64 and cls.REQUIRED_KEYS[0] in data and "salt" in data:
                challenge_b64 = base64.b64encode(
                    json.dumps(data, separators=(",", ":")).encode()
                ).decode()
        if not challenge_b64:
            challenge_b64 = raw.strip('"')

        if not challenge_b64:
            return None, None

        padded = challenge_b64 + ("=" * ((4 - len(challenge_b64) % 4) % 4))
        try:
            decoded = json.loads(base64.b64decode(padded).decode("utf-8"))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            if isinstance(data, dict) and "salt" in data and "challenge" in data:
                return challenge_b64, data
            return challenge_b64, None

        if all(k in decoded for k in cls.REQUIRED_KEYS):
            return challenge_b64, decoded
        if isinstance(data, dict) and all(k in data for k in cls.REQUIRED_KEYS):
            return challenge_b64, data
        return challenge_b64, None

    @classmethod
    def solve_pow(
        cls,
        challenge_data: Dict[str, Any],
        max_iter: int = 1_000_000,
    ) -> Optional[int]:
        algorithm = str(challenge_data.get("algorithm", "SHA-256"))
        salt = str(challenge_data.get("salt", ""))
        expected = str(challenge_data.get("challenge", ""))
        hash_fn = cls.hash_for_algorithm(algorithm)
        limit = max(1, int(max_iter or 1))
        for n in range(limit):
            digest = hash_fn(f"{salt}{n}".encode()).hexdigest()
            if digest == expected:
                return n
        return None

    @classmethod
    def encode_solution(
        cls,
        challenge_data: Dict[str, Any],
        number: int,
        *,
        signature: Optional[str] = None,
        include_signature: bool = False,
    ) -> str:
        payload: Dict[str, Any] = {
            "algorithm": challenge_data.get("algorithm", "SHA-256"),
            "challenge": challenge_data.get("challenge", ""),
            "number": number,
            "salt": challenge_data.get("salt", ""),
        }
        if include_signature:
            payload["signature"] = signature if signature is not None else ""
        elif signature is not None:
            payload["signature"] = signature
        raw = json.dumps(payload, separators=(",", ":"))
        return base64.b64encode(raw.encode()).decode()

    @classmethod
    def version_tuple(cls, version: str) -> Tuple[int, ...]:
        parts = []
        for token in str(version or "").split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:4])

    @classmethod
    def version_less_than(cls, left: str, right: str) -> bool:
        a = cls.version_tuple(left)
        b = cls.version_tuple(right)
        for i in range(max(len(a), len(b))):
            av = a[i] if i < len(a) else 0
            bv = b[i] if i < len(b) else 0
            if av < bv:
                return True
            if av > bv:
                return False
        return False

    def altcha_fetch_challenge(self, path: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        api_path = path if path.startswith("/") else f"/{path}"
        resp = self.http_request(method="GET", path=api_path, allow_redirects=True)
        if not resp or int(resp.status_code or 0) != 200:
            return None, None
        content_type = str((resp.headers or {}).get("Content-Type", "")).lower()
        json_body = None
        if "json" in content_type:
            try:
                json_body = resp.json()
            except Exception:
                json_body = None
        return self.decode_challenge_response(
            resp.text or "",
            content_type=content_type,
            json_body=json_body,
        )

    def altcha_submit(
        self,
        form_path: str,
        field_name: str,
        payload_b64: str,
        extra_fields: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, int, str]:
        api_path = form_path if form_path.startswith("/") else f"/{form_path}"
        data = dict(extra_fields or {})
        data[field_name] = payload_b64
        resp = self.http_request(method="POST", path=api_path, data=data, allow_redirects=True)
        if not resp:
            return False, 0, ""
        code = int(resp.status_code or 0)
        body = (resp.text or "")[:5000]
        body_lower = body.lower()
        captcha_errors = (
            "captcha",
            "bot",
            "verify",
            "invalid altcha",
            "challenge failed",
            "altcha",
        )
        accepted = code in (200, 201, 302, 303) and not any(
            err in body_lower for err in captcha_errors if err != "altcha"
        )
        if "invalid altcha" in body_lower or "challenge failed" in body_lower:
            accepted = False
        return accepted, code, body

    @staticmethod
    def parse_extra_fields(raw: str) -> Dict[str, str]:
        from urllib.parse import parse_qsl

        text = str(raw or "").strip()
        if not text:
            return {}
        return dict(parse_qsl(text, keep_blank_values=True))