#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Travis CI is a Software as a Service (SaaS) based continuous integration service used to build and test softwa."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Travis CI Disclosure Detection',
        'description': 'Travis CI is a Software as a Service (SaaS) based continuous integration service used to build and test software projects. By defining a configuration file named `.travis.yml` in their source code repositories, developers can customize their applications build workflows.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'file', 'config', 'tenable', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/maurosoria/dirsearch/blob/master/db/dicc.txt',
            'https://arstechnica.com/information-technology/2021/09/travis-ci-flaw-exposed-secrets-for-thousands-of-open-source-projects/',
            'https://www.tenable.com/plugins/was/113156',
        ],
    }

    def run(self):
        for path in ('/.travis.yml', '/matomo/.travis.yml', '/ckeditor/.travis.yml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('before_script:', 'jobs:', 'language:',)
            header_any = ('application/octet-stream',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Travis CI Disclosure detected",
                    path=path,
                )
                return True
        return False

