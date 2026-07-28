#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Graphql Sangria Detect."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Graphql Sangria Detect',
        'description': 'Detects Graphql Sangria Detect.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'graphql', 'sangria'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
        },
        'references': ['https://github.com/dolevf/graphw00f/blob/main/graphw00f/lib.py'],
    }

    def run(self):
        for path in ('/graphql', '/api/graphql', '/query', '/'):
            r = self.http_request(
                method='POST',
                path=path,
                allow_redirects=True,
                headers={'Content-Type': 'application/json'},
                data='{"query":"queryy { __typename }"}',
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            # Nuclei: require GraphQL fingerprint, reject HTML responses.
            if 'Syntax error while parsing GraphQL query. Invalid input "queryy", expected ExecutableDefinition or TypeSystemDefinition' not in body:
                continue
            if 'Content-Type: text/html' in headers or 'content-type: text/html' in headers.lower():
                continue
            if '<html' in body.lower() or '<body' in body.lower():
                continue
            self.set_info(
                severity='info',
                reason='Graphql Sangria detected',
                path=path,
            )
            return True
        return False
