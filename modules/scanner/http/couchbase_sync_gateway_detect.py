#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Couchbase Sync Gateway."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Couchbase Sync Gateway Detection',
        'description': 'Detects Couchbase Sync Gateway.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'couchbase'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
        },
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        # Require product banner AND JSON content-type (Nuclei AND).
        if "Couchbase Sync Gateway" not in body:
            return False
        if "application/json" not in headers:
            return False
        self.set_info(
            severity='info',
            reason="Couchbase Sync Gateway detected",
            path='/',
        )
        return True
