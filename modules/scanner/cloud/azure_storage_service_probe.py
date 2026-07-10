#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe Azure Queue, Table, and File storage services for anonymous exposure."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


SERVICE_PATHS = {
    "queue": "/?comp=list",
    "table": "/Tables",
    "file": "/?comp=list",
}


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Azure Storage Service Probe",
        "description": (
            "Probe Azure Queue, Table, and File endpoints for anonymous listing or "
            "readable responses (complements blob-focused modules)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["cloud", "scanner", "azure", "storage", "queue", "table", "file"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    account = OptString("", "Storage account name (e.g. myaccount)", required=True)
    services = OptString("queue,table,file", "Comma-separated services to probe", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _service_list(self):
        raw = str(self.services or "queue,table,file")
        return [item.strip().lower() for item in raw.split(",") if item.strip()]

    def _host_for_service(self, service: str, account: str) -> str:
        suffix = {
            "queue": "queue.core.windows.net",
            "table": "table.core.windows.net",
            "file": "file.core.windows.net",
        }.get(service)
        return f"{account}.{suffix}" if suffix else ""

    def _classify(self, service: str, status_code: int, body: str, headers) -> str:
        text = (body or "").lower()
        hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        if status_code == 200:
            if service == "queue" and "<enumerationresults" in text:
                return "public_listing"
            if service == "table" and ("<feed" in text or "<table" in text):
                return "public_listing"
            if service == "file" and ("<shares>" in text or "<enumerationresults" in text):
                return "public_listing"
            return "accessible"
        if status_code in (401, 403) and any(k.startswith("x-ms-") for k in hdrs):
            return "auth_required"
        if "storage services" in text or "x-ms-" in text:
            return "service_detected"
        return "unknown"

    def run(self):
        account = str(self.account or "").strip().lower()
        if not account:
            print_error("Storage account name is required")
            return False

        findings = []
        for service in self._service_list():
            host = self._host_for_service(service, account)
            if not host:
                continue
            old_target = self.target
            old_port = getattr(self, "port", 443)
            old_ssl = getattr(self, "ssl", True)
            try:
                self.target = host
                self.port = 443
                self.ssl = True
                path = SERVICE_PATHS.get(service, "/")
                resp = self.http_request(method="GET", path=path, allow_redirects=False)
            finally:
                self.target = old_target
                self.port = old_port
                self.ssl = old_ssl

            if not resp:
                continue
            signal = self._classify(service, resp.status_code, resp.text or "", resp.headers)
            item = {
                "service": service,
                "host": host,
                "path": path,
                "status_code": resp.status_code,
                "signal": signal,
            }
            findings.append(item)
            if signal in ("public_listing", "accessible"):
                print_warning(f"[{service}] {host}{path} -> {signal} ({resp.status_code})")
            elif signal == "auth_required":
                print_info(f"[{service}] {host} requires authentication")
            else:
                print_info(f"[{service}] {host} -> {signal}")

        if not findings:
            return False

        exposed = [f for f in findings if f["signal"] in ("public_listing", "accessible")]
        if exposed:
            self.set_info(
                severity="high",
                reason=f"{len(exposed)} Azure storage service(s) anonymously accessible",
                findings=findings,
            )
            if self.output_file:
                self._save(findings)
            return True

        detected = [f for f in findings if f["signal"] != "unknown"]
        if detected:
            self.set_info(severity="info", reason="Azure storage services detected", findings=findings)
            if self.output_file:
                self._save(findings)
            return True
        return False

    def _save(self, findings):
        try:
            with open(str(self.output_file), "w") as fp:
                json.dump({"findings": findings}, fp, indent=2)
            print_success(f"Results saved to {self.output_file}")
        except Exception as exc:
            print_error(f"Failed to save output: {exc}")
