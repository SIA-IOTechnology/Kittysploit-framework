#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HashiCorp Consul version fingerprint."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "HashiCorp Consul version detect",
        "description": "Reads Consul agent self/version from /v1/agent/self.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["consul", "hashicorp", "scanner", "version"],
        "agent": {
            "chain": {"suggested_followups": ["scanner/http/consul_detect"]},
        },
    }

    def run(self):
        for path in ("/v1/agent/self", "/v1/status/leader"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or int(r.status_code or 0) != 200:
                continue
            text = r.text or ""
            version = ""
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    version = str(
                        data.get("Config", {}).get("Version")
                        or data.get("version")
                        or ""
                    )
            except json.JSONDecodeError:
                pass
            if version or "consul" in text.lower():
                self.set_info(
                    severity="info",
                    reason=f"Consul agent API at {path}" + (f" version {version}" if version else ""),
                    version=version or "unknown",
                )
                return True
        return False