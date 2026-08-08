#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Secure, one-time pairing between a KittySploit console and the mobile app."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from interfaces.api_security import RotatingTokenManager, iso_timestamp


class PairingError(ValueError):
    """A pairing code is invalid, expired, or has already been consumed."""


@dataclass
class _PendingPairing:
    code_hash: str
    api_base_url: str
    certificate_sha256: Optional[str]
    created_at: float
    expires_at: float
    consumed: bool = False


class MobilePairingManager:
    """Keep short-lived pairing challenges and paired devices in memory."""

    PROTOCOL_VERSION = 1

    def __init__(
        self,
        token_manager: RotatingTokenManager,
        *,
        access_ttl_seconds: int = 15 * 60,
        refresh_ttl_seconds: int = 30 * 24 * 60 * 60,
    ) -> None:
        self.token_manager = token_manager
        self.access_ttl_seconds = access_ttl_seconds
        self.refresh_ttl_seconds = refresh_ttl_seconds
        self._hash_key = secrets.token_bytes(32)
        self._pending: Dict[str, _PendingPairing] = {}
        self._devices: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def create_pairing(
        self,
        api_base_url: str,
        *,
        certificate_sha256: Optional[str] = None,
        ttl_seconds: int = 120,
    ) -> Dict[str, Any]:
        ttl_seconds = max(30, min(int(ttl_seconds), 600))
        code = secrets.token_urlsafe(24)
        code_hash = self._hash_code(code)
        now = time.time()
        endpoint = api_base_url.rstrip("/")
        fingerprint = self._normalize_fingerprint(certificate_sha256)
        pending = _PendingPairing(
            code_hash=code_hash,
            api_base_url=endpoint,
            certificate_sha256=fingerprint,
            created_at=now,
            expires_at=now + ttl_seconds,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._pending[code_hash] = pending

        query = {
            "v": str(self.PROTOCOL_VERSION),
            "endpoint": endpoint,
            "code": code,
        }
        if fingerprint:
            query["fingerprint"] = f"sha256:{fingerprint}"
        return {
            "pairing_uri": f"kittysploit://pair?{urlencode(query)}",
            "expires_at": iso_timestamp(pending.expires_at),
            "expires_in": ttl_seconds,
            "api_base_url": endpoint,
            "certificate_sha256": fingerprint,
        }

    def claim(
        self,
        code: str,
        *,
        device_name: str,
        workspace: str = "default",
    ) -> Dict[str, Any]:
        raw_code = str(code or "").strip()
        clean_name = " ".join(str(device_name or "").strip().split())[:80]
        if not raw_code or not clean_name:
            raise PairingError("A pairing code and device name are required.")

        code_hash = self._hash_code(raw_code)
        now = time.time()
        with self._lock:
            pending = self._pending.get(code_hash)
            if (
                pending is None
                or pending.consumed
                or pending.expires_at <= now
            ):
                raise PairingError("Invalid or expired pairing code.")
            # Consume before token issuance so concurrent requests cannot replay it.
            pending.consumed = True

        device_id = uuid.uuid4().hex
        subject = f"mobile:{device_id}"
        token_data = self.token_manager.issue_pair(
            subject=subject,
            roles=("viewer",),
            access_ttl_seconds=self.access_ttl_seconds,
            refresh_ttl_seconds=self.refresh_ttl_seconds,
            metadata={
                "issuer": "mobile_pairing",
                "device_id": device_id,
                "device_name": clean_name,
            },
        )
        device = {
            "id": device_id,
            "name": clean_name,
            "paired_at": iso_timestamp(now),
            "workspace": workspace or "default",
            "revoked": False,
        }
        with self._lock:
            self._devices[device_id] = device

        return {
            "pairing_version": self.PROTOCOL_VERSION,
            "api_base_url": pending.api_base_url,
            "certificate_sha256": pending.certificate_sha256,
            "device": dict(device),
            "workspace": device["workspace"],
            **token_data,
        }

    def list_devices(self) -> list[Dict[str, Any]]:
        with self._lock:
            return [dict(device) for device in self._devices.values()]

    def pending_count(self) -> int:
        with self._lock:
            self._cleanup_locked(time.time())
            return sum(1 for item in self._pending.values() if not item.consumed)

    def revoke_device(self, device_id: str) -> bool:
        with self._lock:
            device = self._devices.get(str(device_id or "").strip())
            if not device or device["revoked"]:
                return False
            device["revoked"] = True
        self.token_manager.revoke_subject(f"mobile:{device_id}")
        return True

    def _hash_code(self, code: str) -> str:
        return hmac.new(
            self._hash_key,
            code.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _normalize_fingerprint(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        normalized = str(value).lower().replace("sha256:", "").replace(":", "").strip()
        if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
            raise ValueError("certificate_sha256 must be a SHA-256 hex digest")
        return normalized

    def _cleanup_locked(self, now: float) -> None:
        stale = [
            key
            for key, item in self._pending.items()
            if item.expires_at <= now or item.consumed
        ]
        for key in stale:
            self._pending.pop(key, None)
