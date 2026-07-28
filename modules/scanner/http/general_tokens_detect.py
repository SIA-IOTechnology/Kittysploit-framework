#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect likely exposed API tokens / secrets in HTML responses."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Generic Tokens Detection',
        'description': 'Detects likely exposed API tokens or secrets in HTTP responses.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'token', 'generic', 'vuln'],
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
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
    }

    # High-signal secret shapes only (previous port used Nuclei negative-match noise as positives).
    _PATTERNS = (
        (r"(?i)['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "api_key"),
        (r"(?i)['\"]?secret[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]", "secret_key"),
        (r"(?i)['\"]?access[_-]?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-.]{20,}['\"]", "access_token"),
        (r"(?i)['\"]?auth[_-]?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-.]{20,}['\"]", "auth_token"),
        (r"(?i)\bAKIA[0-9A-Z]{16}\b", "aws_access_key"),
        (r"(?i)\bghp_[A-Za-z0-9]{36}\b", "github_pat"),
        (r"(?i)\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "slack_token"),
    )

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        hits = []
        for rx, label in self._PATTERNS:
            if re.search(rx, body):
                hits.append(label)
        if not hits:
            return False
        self.set_info(
            severity='info',
            reason=f"possible exposed token(s): {', '.join(sorted(set(hits)))}",
            path=path,
        )
        return True
