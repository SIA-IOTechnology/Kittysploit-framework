#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated Elasticsearch index enumeration."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Elasticsearch Indices Verification",
        "description": "Confirms anonymous access to Elasticsearch _cat/indices or cluster health.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["elasticsearch", "database", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["db_access", "unauth_read"]},
        },
    }

    def _parse_json(self, response):
        if not response or response.status_code != 200:
            return None
        try:
            return response.json()
        except Exception:
            try:
                return json.loads(response.text or "")
            except Exception:
                return None

    def run(self):
        for path in ("/_cat/indices?format=json", "/_cluster/health"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data = self._parse_json(r)
            if data is None:
                continue
            if isinstance(data, list) and data:
                names = [str(item.get("index", "")) for item in data if isinstance(item, dict)][:10]
                self.set_info(
                    severity="high",
                    reason="Elasticsearch index list readable without authentication",
                    index_count=len(data),
                    indices=",".join(names),
                    confidence="high",
                )
                return True
            if isinstance(data, dict) and data.get("cluster_name"):
                self.set_info(
                    severity="high",
                    reason="Elasticsearch cluster health readable without authentication",
                    cluster=str(data.get("cluster_name")),
                    confidence="high",
                )
                return True
        return False
