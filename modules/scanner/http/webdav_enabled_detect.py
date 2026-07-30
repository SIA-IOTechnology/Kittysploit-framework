#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect enabled WebDAV (PROPFIND)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = ("/", "/webdav/", "/DavWWWRoot/", "/remote.php/dav/", "/dav/")


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WebDAV Enabled",
        "description": (
            "Detects WebDAV by issuing PROPFIND and looking for Multi-Status / DAV "
            "response markers."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc4918",
        ],
        "tags": ["web", "scanner", "webdav", "propfind", "misconfig", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.2,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "file_read", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
    }

    def _url(self, path: str) -> str:
        host = str(getattr(getattr(self, "target", None), "value", getattr(self, "target", "")) or "").strip()
        port = getattr(getattr(self, "port", None), "value", getattr(self, "port", 80))
        ssl = getattr(getattr(self, "ssl", None), "value", getattr(self, "ssl", False))
        scheme = "https" if ssl in (True, "true", "True", 1, "1") else "http"
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            port_i = 443 if scheme == "https" else 80
        if host.startswith(("http://", "https://")):
            return host.rstrip("/") + path
        return f"{scheme}://{host}:{port_i}{path}"

    def run(self):
        propfind_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/></d:prop></d:propfind>'
        )
        for path in PATHS:
            response = self.http_request(
                method="PROPFIND",
                path=path,
                allow_redirects=False,
                headers={
                    "Depth": "0",
                    "Content-Type": "application/xml",
                },
                data=propfind_body,
            )
            if not response:
                continue
            status = int(getattr(response, "status_code", 0) or 0)
            # 207 Multi-Status is the classic WebDAV success
            if status not in (207, 200):
                continue
            headers = {str(k).lower(): str(v) for k, v in dict(response.headers or {}).items()}
            body = response.text or ""
            dav = headers.get("dav") or headers.get("DAV") or ""
            body_l = body.lower()
            looks_webdav = (
                "DAV:" in body
                or "<d:response" in body_l
                or "<d:multistatus" in body_l
                or "multistatus" in body_l
                or bool(dav)
            )
            if status == 207 or looks_webdav:
                self.report_finding(
                    "WebDAV enabled",
                    severity="medium",
                    evidence={
                        "url": self._url(path),
                        "status_code": status,
                        "path": path,
                        "dav_header": dav[:120],
                        "snippet": body[:240].replace("\n", " "),
                    },
                    impact={
                        "summary": "WebDAV can allow remote file listing and sometimes upload/modification.",
                        "business_risk": "Unauthorized file access or content tampering",
                    },
                    remediation={
                        "summary": "Disable WebDAV unless required; otherwise enforce strong auth and ACLs.",
                        "actions": [
                            "Disable PROPFIND/WebDAV modules if unused",
                            "Require authentication for DAV paths",
                            "Restrict write methods (PUT/DELETE/MKCOL) at the proxy",
                        ],
                    },
                )
                return True
        return False
