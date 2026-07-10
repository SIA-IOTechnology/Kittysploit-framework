#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{0,20000}?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_SERVICE_ACCOUNT_TYPE = re.compile(
    r'(?:\\?"type\\?"|["\']type["\'])\s*:\s*(?:\\?"service_account\\?"|["\']service_account["\'])',
    re.IGNORECASE,
)
_SERVICE_ACCOUNT_EMAIL = re.compile(
    r'(?:\\?"client_email\\?"|["\']client_email["\'])\s*:\s*(?:\\?"([^"\\]+)\\?"|["\']([^"\']+)["\'])',
    re.IGNORECASE,
)
_GCP_PRIVATE_KEY_JSON = re.compile(
    r'(?:"private_key"|\\"private_key\\")\s*:\s*("(?:\\.|[^"\\])*")',
    re.IGNORECASE | re.DOTALL,
)
_AWS_ACCESS_KEY_ID = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_AWS_SECRET_KEY_JSON = re.compile(
    r'["\']?(?:aws_secret_access_key|secret_access_key)["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    re.IGNORECASE,
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HTTP response — credential leak detect",
        "description": (
            "Scans an HTTP response body for exposed credentials: PEM private keys, Google "
            "service account JSON, AWS keys. Returns leaked values in output. Use proxy_flow_id "
            "or response_body_b64 for a captured KittyProxy flow."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["scanner", "http", "credentials", "disclosure", "secrets", "proxy"],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
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

    path = OptString("/", "Request path when fetching live (ignored if captured body is set)", required=False)
    http_method = OptString("GET", "HTTP method for live fetch", required=False)
    proxy_flow_id = OptString(
        "",
        "KittyProxy flow ID — loads the captured response body (set automatically from Analyze)",
        required=False,
        advanced=True,
    )
    response_body_b64 = OptString(
        "",
        "Base64-encoded response body to scan (optional)",
        required=False,
        advanced=True,
    )

    def _o(self, opt):
        if hasattr(opt, "value"):
            return opt.value
        if hasattr(opt, "__get__"):
            try:
                return opt.__get__(self, type(self))
            except Exception:
                pass
        return opt

    def _resolve_body(self) -> tuple:
        """Return (body_text, source_label)."""
        b64 = str(self._o(self.response_body_b64) or "").strip()
        if b64:
            try:
                raw = base64.b64decode(b64)
                return raw.decode("utf-8", errors="replace"), "captured KittyProxy response"
            except Exception as e:
                print_error(f"Invalid response_body_b64: {e}")
                return "", "invalid base64"

        flow_id = str(self._o(self.proxy_flow_id) or "").strip()
        if flow_id:
            print_warning(
                "proxy_flow_id is set but response_body_b64 is empty — re-run Execute from Analyze "
                "or set response_body_b64 from the captured flow."
            )

        method = str(self._o(self.http_method) or "GET").upper()
        path = str(self._o(self.path) or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path

        print_status(f"Live HTTP {method} {path}")
        r = self.http_request(method=method, path=path, allow_redirects=True)
        if not r:
            print_error("No HTTP response")
            return "", "no response"
        code = getattr(r, "status_code", None)
        try:
            text = r.text or ""
        except Exception:
            text = ""
        return text, f"live HTTP {code}"

    @staticmethod
    def _json_unescape_string(raw: str) -> str:
        s = raw.strip()
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            try:
                return json.loads(s)
            except Exception:
                return s[1:-1].replace("\\n", "\n").replace("\\r", "\r").replace('\\"', '"')
        return s

    @staticmethod
    def _extract_json_object_at(content: str, anchor: int) -> str:
        start = content.rfind("{", 0, anchor + 1)
        if start < 0:
            return ""
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(content)):
            ch = content[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return content[start : i + 1]
        return ""

    def _scan_body(self, content: str) -> list:
        if not content or len(content) < 24:
            return []

        findings = []
        seen = set()

        def add(kind: str, name: str, value: str, detail: str = "") -> None:
            val_key = (kind, (value or "")[:200])
            if val_key in seen:
                return
            seen.add(val_key)
            findings.append({
                "kind": kind,
                "name": name,
                "value": value,
                "detail": detail or name,
            })

        for match in _PEM_PRIVATE_KEY.finditer(content):
            pem = match.group(0).strip()
            inner = re.sub(
                r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
                "",
                pem,
                flags=re.IGNORECASE,
            )
            inner = re.sub(r"[^A-Za-z0-9+/=]", "", inner)
            if len(inner) < 80:
                continue
            add("private_key", "PEM private key", pem, "Full PEM block from response body")
            break

        for m in _GCP_PRIVATE_KEY_JSON.finditer(content):
            raw = m.group(1)
            pem = self._json_unescape_string(raw)
            if "BEGIN" in pem and "PRIVATE KEY" in pem:
                add("private_key", "JSON private_key field", pem, "private_key value from JSON")
                break

        sa_positions = [m.start() for m in _SERVICE_ACCOUNT_TYPE.finditer(content)]
        for pos in sa_positions:
            blob = self._extract_json_object_at(content, pos)
            if not blob or len(blob) < 40:
                continue
            try:
                parsed = json.loads(blob)
            except Exception:
                parsed = None
            if isinstance(parsed, dict) and str(parsed.get("type", "")).lower() == "service_account":
                email = parsed.get("client_email") or parsed.get("clientEmail") or "service_account"
                add(
                    "service_account",
                    str(email),
                    json.dumps(parsed, indent=2),
                    "Full service_account JSON object",
                )
            else:
                add("service_account", "service_account JSON", blob, "Raw JSON around type=service_account")
            break

        email_match = _SERVICE_ACCOUNT_EMAIL.search(content)
        if email_match and not any(f["kind"] == "service_account" for f in findings):
            client_email = (email_match.group(1) or email_match.group(2) or "").strip()
            ctx = self._extract_json_object_at(content, email_match.start())
            if ctx:
                add("service_account", client_email, ctx, "JSON fragment containing client_email")
            else:
                add("service_account", client_email, client_email, "client_email field only")

        for m in _AWS_ACCESS_KEY_ID.finditer(content):
            add("aws_access_key", m.group(1), m.group(1), "AWS access key id")
            break

        for m in _AWS_SECRET_KEY_JSON.finditer(content):
            secret = m.group(1)
            add("aws_secret_key", "AWS secret access key", secret, "aws_secret_access_key value")
            break

        return findings

    def _print_leaked_credentials(self, findings: list) -> None:
        print_success(f"=== {len(findings)} leaked credential(s) ===")
        for i, f in enumerate(findings, 1):
            print_warning(f"[{i}] {f['kind']} — {f['name']}")
            if f.get("detail"):
                print_info(f"    {f['detail']}")
            value = f.get("value") or ""
            if "\n" in value or len(value) > 120:
                print_info("    --- value ---")
                for line in value.splitlines():
                    print_info(f"    {line}")
                print_info("    -------------")
            else:
                print_info(f"    value: {value}")

    def run(self):
        body, source = self._resolve_body()
        if not body:
            self.set_info(reason="No response body to scan", confidence="low")
            return False

        print_info(f"Scanning {len(body)} bytes from {source}")
        findings = self._scan_body(body)

        if not findings:
            print_status("No credential leak patterns found in response body")
            self.set_info(reason="No PEM / service account / AWS key patterns", confidence="high")
            return False

        self._print_leaked_credentials(findings)

        payload = {
            "source": source,
            "count": len(findings),
            "leaked_credentials": [
                {"kind": f["kind"], "name": f["name"], "value": f["value"], "detail": f.get("detail", "")}
                for f in findings
            ],
        }
        print_info("Structured result (JSON):")
        print_info(json.dumps(payload, indent=2, ensure_ascii=False))

        kinds = ", ".join(f["kind"] for f in findings)
        self.set_info(
            severity="critical",
            reason=f"Exposed credential(s) in {source}: {kinds}",
            confidence="high",
            leaked_credentials=payload["leaked_credentials"],
        )
        return payload
