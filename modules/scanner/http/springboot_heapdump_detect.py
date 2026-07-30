#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Boot Actuator heapdump exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = (
    "/heapdump",
    "/actuator/heapdump",
    "/manage/heapdump",
    "/management/heapdump",
    "/bbo-admin/heapdump",
    "/bbo-admin/actuator/heapdump",
    "/bbo-rest/heapdump",
    "/bbo-rest/actuator/heapdump",
    "/bbo-search/heapdump",
    "/bbo-search/actuator/heapdump",
    "/bbo-token/heapdump",
    "/bbo-token/actuator/heapdump",
    "/bbo-vin/heapdump",
    "/bbo-vin/actuator/heapdump",
)

_GZIP_MAGIC = b"\x1f\x8b\x08"
_JAVA_PROFILE = b"JAVA PROFILE"
_HPROF = b"HPROF"


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Spring Boot Actuator Heap Dump",
        "description": (
            "Detects exposed Spring Boot Actuator heapdump endpoints that can leak "
            "JVM memory, secrets, and HTTP traffic."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "references": [
            "https://github.com/pyn3rd/Spring-Boot-Vulnerability",
        ],
        "tags": ["web", "scanner", "springboot", "actuator", "exposure", "misconfig", "vuln"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 14,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.2,
            "noise": 0.5,
            "value": 1.5,
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

    def _looks_like_heapdump(self, content: bytes) -> bool:
        if not content:
            return False
        head = content[:64]
        if head.startswith(_GZIP_MAGIC):
            return True
        if _JAVA_PROFILE in head or _HPROF in head:
            return True
        return False

    def run(self):
        # Baseline: random path should NOT look like a heap dump
        import uuid

        baseline = self.http_request(
            method="GET",
            path=f"/{uuid.uuid4().hex[:8]}",
            allow_redirects=False,
            stream=True,
        )
        baseline_hit = False
        if baseline is not None:
            try:
                baseline_hit = self._looks_like_heapdump((baseline.content or b"")[:256])
            except Exception:
                baseline_hit = False
        if baseline_hit:
            # Soft-404 / catch-all returning binary junk — avoid FPs
            return False

        for path in PATHS:
            response = self.http_request(
                method="GET",
                path=path,
                allow_redirects=False,
                stream=True,
            )
            if not response or response.status_code != 200:
                continue
            try:
                # Cap read ~2MB to avoid downloading huge dumps
                chunk = b""
                if getattr(response, "raw", None) is not None and getattr(response, "iter_content", None):
                    for part in response.iter_content(chunk_size=65536):
                        if not part:
                            break
                        chunk += part
                        if len(chunk) >= 2097152:
                            break
                else:
                    chunk = (response.content or b"")[:2097152]
            except Exception:
                try:
                    chunk = (response.content or b"")[:2097152]
                except Exception:
                    continue

            if not self._looks_like_heapdump(chunk):
                continue

            kind = "gzip" if chunk.startswith(_GZIP_MAGIC) else "hprof"
            self.report_finding(
                "Spring Boot Actuator heap dump exposed",
                severity="critical",
                evidence={
                    "url": self._url(path),
                    "status_code": int(response.status_code),
                    "path": path,
                    "format": kind,
                    "bytes_sampled": len(chunk),
                },
                impact={
                    "summary": "JVM heap snapshots can leak secrets, tokens, and request data from memory.",
                    "business_risk": "Critical memory and credential disclosure",
                },
                remediation={
                    "summary": "Disable or protect Actuator heapdump endpoints.",
                    "actions": [
                        "Disable heapdump actuator endpoint in production",
                        "Require authentication / network allow-lists for Actuator",
                        "Rotate secrets that may have been present in memory",
                    ],
                },
            )
            return True
        return False
