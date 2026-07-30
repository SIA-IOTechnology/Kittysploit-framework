#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""BloodHound Community Edition / Enterprise API client (stub + usable upload helpers)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib import error, request


@dataclass
class BHCEConfig:
    base_url: str
    token_id: str = ""
    token_key: str = ""
    timeout: float = 30.0

    @property
    def origin(self) -> str:
        return str(self.base_url or "").rstrip("/")


class BHCEClient:
    """Minimal BHCE REST client for version check + file upload job.

    Auth uses BloodHound API tokens (BHE/BHCE v5+ style headers). Methods that
    need a live server raise clear errors when unreachable — safe for offline use.
    """

    def __init__(self, config: BHCEConfig):
        self.config = config

    def _headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "KittySploit-BHCE/1.0",
            "Accept": "application/json",
        }
        if self.config.token_key:
            # BHCE/BHE token auth variants
            headers["Authorization"] = f"Bearer {self.config.token_key}"
            if self.config.token_id:
                headers["TokenId"] = self.config.token_id
        return headers

    def _url(self, path: str) -> str:
        return f"{self.config.origin}/{path.lstrip('/')}"

    def request_json(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(self._url(path), data=data, method=method.upper(), headers=headers)
        try:
            with request.urlopen(req, timeout=float(self.config.timeout)) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {}
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"BHCE HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"BHCE unreachable at {self.config.origin}: {exc.reason}") from exc

    def version(self) -> Dict[str, Any]:
        """GET /api/version — connectivity smoke test."""
        return self.request_json("GET", "/api/version")

    def upload_file(self, local_path: str) -> Dict[str, Any]:
        """
        Upload a SharpHound zip/JSON to BHCE file ingest (best-effort).

        Endpoint paths vary by BHCE version; this tries common ones and returns
        the first successful response. Operators should verify in the BH UI.
        """
        path = Path(local_path)
        if not path.is_file():
            raise FileNotFoundError(local_path)
        content = path.read_bytes()
        candidates = [
            "/api/v2/file-upload/start",
            "/api/v2/file-upload",
            "/api/bloodhound-ce/upload",
        ]
        errors = []
        for endpoint in candidates:
            try:
                # Many BHCE builds want multipart; send raw with filename hint first
                headers = self._headers()
                headers["Content-Type"] = "application/octet-stream"
                headers["X-File-Name"] = path.name
                req = request.Request(
                    self._url(endpoint),
                    data=content,
                    method="POST",
                    headers=headers,
                )
                with request.urlopen(req, timeout=float(self.config.timeout)) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    payload = json.loads(raw) if raw.strip().startswith("{") else {"raw": raw}
                    payload["_endpoint"] = endpoint
                    payload["_status"] = getattr(resp, "status", 200)
                    return payload
            except Exception as exc:
                errors.append(f"{endpoint}: {exc}")
                continue
        raise RuntimeError(
            "BHCE upload failed on all known endpoints. "
            "Import the zip manually in BloodHound UI, or set bloodhound_export_path "
            f"for local KittySploit graph import. Attempts: {'; '.join(errors[:3])}"
        )

    def wait_stub(self, seconds: float = 1.0) -> None:
        """Placeholder for async job polling (future BHCE job status)."""
        time.sleep(max(0.0, float(seconds)))


def client_from_env_or_opts(
    *,
    base_url: str = "",
    token_id: str = "",
    token_key: str = "",
) -> Optional[BHCEClient]:
    import os

    url = (base_url or os.environ.get("KITTYSPLOIT_BHCE_URL") or "").strip()
    if not url:
        return None
    return BHCEClient(
        BHCEConfig(
            base_url=url,
            token_id=(token_id or os.environ.get("KITTYSPLOIT_BHCE_TOKEN_ID") or "").strip(),
            token_key=(token_key or os.environ.get("KITTYSPLOIT_BHCE_TOKEN") or "").strip(),
        )
    )
