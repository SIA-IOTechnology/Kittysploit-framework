#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inspired by FireSploit (Shubham Sharma): RTDB REST public read / optional write probe.
https://github.com/secshubhamsharma/FireSploit
"""

import json
import secrets
from urllib.parse import urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Firebase Realtime Database — public REST access",
        "description": (
            "GET `/.json?shallow=true` on the Realtime Database root to see if rules allow unauthenticated "
            "reads. Optionally PUT+GET+DELETE a random key when `probe_write` is enabled (only on assets "
            "you are authorized to test)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "references": [
            "https://firebase.google.com/docs/database/rest/usage",
            "https://firebase.google.com/docs/database/security",
            "https://github.com/secshubhamsharma/FireSploit",
        ],
        "tags": ["scanner", "http", "firebase", "rtdb", "misconfiguration", "rules"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    database_url = OptString(
        "",
        "RTDB root (https://PROJECT.firebaseio.com or https://…firebasedatabase.app); "
        "if empty, uses https://<target> when target hostname looks like RTDB",
        required=False,
    )
    probe_write = OptBool(
        False,
        "PUT a probe JSON document then DELETE it (intrusive — only with explicit permission)",
        required=False,
        advanced=True,
    )
    read_timeout = OptInteger(8, "HTTP timeout (seconds)", required=False, advanced=True)

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        if hasattr(opt, "__get__"):
            try:
                return opt.__get__(self, type(self))
            except Exception:
                pass
        return opt

    def _verify(self):
        return self._to_bool(self._o(self.verify_ssl))

    def _timeout(self) -> float:
        return float(self._o(self.read_timeout) or 8)

    @staticmethod
    def _normalize_rtdb_root(url: str) -> str:
        u = (url or "").strip().rstrip("/")
        if not u:
            return ""
        if not u.lower().startswith("http"):
            u = "https://" + u
        p = urlparse(u)
        if not p.netloc:
            return ""
        return f"{p.scheme}://{p.netloc}"

    def _resolve_base(self) -> str:
        raw = str(self._o(self.database_url) or "").strip()
        if raw:
            return self._normalize_rtdb_root(raw)
        host = str(self._o(self.target) or "").strip().lower()
        if ".firebaseio.com" in host or "firebasedatabase.app" in host:
            return self._normalize_rtdb_root(host)
        return ""

    @staticmethod
    def _firebase_permission_error(data) -> bool:
        if data is None:
            return False
        if isinstance(data, dict):
            err = data.get("error")
            if err is None:
                return False
            if isinstance(err, str) and "permission" in err.lower():
                return True
            if isinstance(err, dict):
                blob = json.dumps(err).lower()
                return "permission" in blob or "denied" in blob
        return False

    def _get_json(self, url: str):
        to = self._timeout()
        verify = self._verify()
        try:
            self._configure_session()
            r = self.session.get(url, timeout=to, verify=verify, allow_redirects=True)
            text = (r.text or "").strip()
            try:
                data = r.json() if text else None
            except Exception:
                data = None
            return r.status_code, data, text[:2000], None
        except Exception as e:
            return -1, None, "", str(e)

    def _check_public_read(self, base: str):
        """GET /.json?shallow=true — small payload; 200 without Firebase error object => read allowed."""
        url = f"{base}/.json?shallow=true"
        code, data, snippet, err = self._get_json(url)
        if err:
            return False, f"read probe failed: {err}", code
        if code in (401, 403):
            return False, "rules deny anonymous read (HTTP 401/403)", code
        if code == 404:
            return False, "HTTP 404 (wrong host or database not found)", code
        if code != 200:
            return False, f"unexpected HTTP {code}", code
        if self._firebase_permission_error(data):
            return False, "rules deny read (error object in JSON body)", code
        preview = snippet if snippet else "null or empty body"
        return True, f"anonymous read allowed at root (shallow preview: {preview})", code

    def _probe_write(self, base: str):
        token = secrets.token_hex(4)
        key = f"kittysploit_rtdb_probe_{token}"
        put_url = f"{base}/{key}.json"
        payload = {"probe": True, "by": "kittysploit-rtdb-scanner", "token": token}
        to = self._timeout()
        verify = self._verify()
        try:
            self._configure_session()
            pr = self.session.put(put_url, json=payload, timeout=to, verify=verify)
            if pr.status_code not in (200, 201):
                return False, f"PUT rejected HTTP {pr.status_code}"
            gr = self.session.get(put_url, timeout=to, verify=verify)
            if gr.status_code != 200:
                return False, "PUT accepted but GET follow-up failed"
            try:
                got = gr.json()
            except Exception:
                got = None
            if self._firebase_permission_error(got):
                return False, "PUT accepted but read-back looks like rules denial"
            self.session.delete(put_url, timeout=to, verify=verify)
            return True, f"anonymous write+read verified at /{key}.json (then deleted)"
        except Exception as e:
            return False, f"write probe error: {e}"

    def run(self):
        base = self._resolve_base()
        if not base:
            host = str(self._o(self.target) or "").strip().lower()
            if "firestore.googleapis.com" in host or (
                "googleapis.com" in host and "firestore" in host
            ):
                self.set_info(
                    reason=(
                        "This module probes Firebase Realtime Database (*.firebaseio.com), "
                        "not Firestore HTTP streams. For private_key / service_account in a "
                        "captured response, use scanner/http/http_response_credential_leak_detect."
                    )
                )
            else:
                self.set_info(
                    reason="Set database_url to your RTDB root, or set target to *.firebaseio.com / *.firebasedatabase.app"
                )
            return False

        read_ok, read_msg, http_code = self._check_public_read(base)
        parts = [f"base={base}", read_msg]
        write_ok = False
        write_msg = ""

        if self._to_bool(self._o(self.probe_write)):
            write_ok, write_msg = self._probe_write(base)
            parts.append(write_msg)

        self.set_info(
            http=http_code,
            reason="; ".join(parts),
            read_public=read_ok,
            write_public=write_ok if self._to_bool(self._o(self.probe_write)) else None,
        )

        if read_ok or write_ok:
            return True
        return False
