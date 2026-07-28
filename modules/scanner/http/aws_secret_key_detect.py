#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects AWS Secret Key."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AWS Secret Key Detection',
        'description': 'Detects AWS Access Key ID + Secret Key co-occurring in HTTP responses.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'aws', 'tokens', 'vuln'],
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
        'references': [
            'https://docs.aws.amazon.com/cli/latest/reference/sts/get-access-key-info.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        # Nuclei uses AND: AKIA access-key id AND a 40-char secret-like token.
        # OR alone on the 40-char pattern matches almost any minified JS/CSS.
        if not re.search(r'\bAKIA[0-9A-Z]{16}\b', body):
            return False
        if not re.search(r'\b[A-Za-z0-9/+=]{40}\b', body):
            return False
        self.set_info(
            severity='info',
            reason="AWS access key id + secret-like token detected",
            path='/',
        )
        return True
