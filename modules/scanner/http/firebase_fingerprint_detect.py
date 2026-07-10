#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Marqueurs HTML / JS (hors URLs génériques trop bruyantes)
_BODY_MARKERS = [
    "__FIREBASE_DEFAULTS__",
    "firebase.initializeApp",
    "initializeApp({",
    "getApps()",
    "firebase/auth",
    "firebase/firestore",
    "firebase/storage",
    "firebase/messaging",
    "firebaseapp.com",
    "firebasestorage.googleapis.com",
    "firestore.googleapis.com",
    "identitytoolkit.googleapis.com",
    "securetoken.googleapis.com",
    "firebase.googleapis.com",
]

_HEADER_HINTS = (
    "x-firebase-hosting",
    "x-firebase-request-type",
    "x-firebase-storage-version",
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Firebase stack & hosting init — detect",
        "description": (
            "Passive recon: reads the configured path for Firebase SDK / API hints, checks response "
            "headers, and optionally GETs `__/firebase/init.json` (Firebase Hosting auto-config). "
            "Positive when init.json returns a project config or strong in-page markers "
            "(`__FIREBASE_DEFAULTS__`, etc.)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": [
            "https://firebase.google.com/docs/hosting/reserved-urls",
            "https://firebase.google.com/docs/projects/learn-more#config-files-objects",
        ],
        "tags": ["scanner", "http", "firebase", "hosting", "recon", "disclosure"],
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

    probe_init_json = OptBool(True, "GET /__/firebase/init.json (Hosting reserved URL)", required=False)
    probe_messaging_sw = OptBool(True, "GET /firebase-messaging-sw.js", required=False)

    def _get_text(self, r):
        if not r or not hasattr(r, "text"):
            return ""
        try:
            return r.text or ""
        except Exception:
            return ""

    def _header_blob(self, r):
        if not r or not hasattr(r, "headers"):
            return ""
        try:
            return " ".join(f"{k}: {v}" for k, v in r.headers.items())
        except Exception:
            return ""

    def _try_init_json(self):
        if not self._o(self.probe_init_json):
            return None, None
        r = self.http_request(method="GET", path="/__/firebase/init.json", allow_redirects=True)
        if not r or r.status_code != 200:
            return None, None
        ct = (r.headers.get("Content-Type") or "").lower()
        if "json" not in ct and not (r.text or "").strip().startswith("{"):
            return None, None
        try:
            data = r.json()
        except Exception:
            try:
                data = json.loads((r.text or "").strip())
            except Exception:
                return None, None
        if not isinstance(data, dict):
            return None, None
        pid = (data.get("projectId") or data.get("project_id") or "").strip()
        if pid:
            return data, pid
        return None, None

    def _try_messaging_sw(self):
        if not self._o(self.probe_messaging_sw):
            return False, None
        r = self.http_request(method="GET", path="/firebase-messaging-sw.js", allow_redirects=True)
        if not r or r.status_code != 200:
            return False, None
        t = self._get_text(r).lower()
        if "firebase" in t and ("messaging" in t or "importscripts" in t):
            return True, r.status_code
        return False, None

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        if hasattr(opt, "__get__"):
            try:
                return opt.__get__(self, type(self))
            except Exception:
                pass
        return opt

    @staticmethod
    def _project_from_body(text):
        if not text:
            return None
        m = re.search(r'"projectId"\s*:\s*"([^"\\]+)"', text)
        if m:
            return m.group(1).strip()
        m = re.search(r"projectId\s*:\s*['\"]([^'\"\\]+)['\"]", text, re.I)
        if m:
            return m.group(1).strip()
        return None

    def run(self):
        path = str(self.path).strip() or "/"
        if not path.startswith("/"):
            path = "/" + path

        r = self.http_request(method="GET", path=path, allow_redirects=True)
        if not r:
            self.set_info(reason="No response from target")
            return False

        body = self._get_text(r)
        hdr = self._header_blob(r).lower()
        markers = [m for m in _BODY_MARKERS if m.lower() in body.lower()]
        header_hits = [h for h in _HEADER_HINTS if h in hdr]

        strong = False
        reasons = []

        init_data, init_pid = self._try_init_json()
        if init_pid:
            strong = True
            reasons.append(f"__/firebase/init.json exposes projectId={init_pid!r}")
            if init_data.get("apiKey"):
                reasons.append("init.json includes apiKey (expected public identifier; still map surface)")

        if "__FIREBASE_DEFAULTS__" in body:
            strong = True
            pj = self._project_from_body(body)
            if pj:
                reasons.append(f"__FIREBASE_DEFAULTS__ / inline config mentions projectId={pj!r}")
            else:
                reasons.append("__FIREBASE_DEFAULTS__ present in page")

        msg_hit, msg_code = self._try_messaging_sw()
        if msg_hit:
            strong = True
            reasons.append(f"/firebase-messaging-sw.js returned HTTP {msg_code} with Firebase messaging code")

        if markers and not strong:
            reasons.append("soft signals: " + ", ".join(markers[:6]) + ("…" if len(markers) > 6 else ""))
        if header_hits:
            reasons.append("headers: " + ", ".join(header_hits))

        detail = "; ".join(reasons) if reasons else "no Firebase markers"
        self.set_info(
            http=r.status_code,
            reason=detail,
            confidence="high" if strong else ("medium" if markers or header_hits else "low"),
        )

        if strong:
            return True
        if header_hits:
            return True
        if len(markers) >= 2:
            return True
        return False
