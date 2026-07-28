#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects pages whose visible copyright year looks outdated."""

import re
from datetime import datetime

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Find Pages with Old Copyright Dates Detection',
        'description': 'Detects pages that still display a copyright year older than the current year.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misc', 'miscellaneous', 'generic'],
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
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        # Match "Copyright 2019", "© 2015-2018", "&copy; 2012", etc.
        pattern = re.compile(
            r'(?:copyright|©|&copy;|&#169;)\s*'
            r'(?:\(c\)\s*)?'
            r'(?:19|20)\d{2}'
            r'(?:\s*[-–—]\s*((?:19|20)\d{2}))?',
            re.I,
        )
        current_year = datetime.utcnow().year
        years = []
        for m in pattern.finditer(body):
            # Prefer end year of a range when present
            if m.group(1):
                years.append(int(m.group(1)))
            else:
                y = re.search(r'((?:19|20)\d{2})\s*$', m.group(0))
                if y:
                    years.append(int(y.group(1)))
        if not years:
            return False
        newest = max(years)
        # Only flag when the newest visible copyright year is clearly stale
        if newest >= current_year - 1:
            return False
        self.set_info(
            severity='info',
            reason=f"outdated copyright year displayed ({newest})",
            path='/',
            copyright_year=newest,
        )
        return True
